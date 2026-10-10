use super::*;
use perp_core::Market;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
};

const NOW: u64 = 1_000_000;
fn key() -> SigningKey {
    SigningKey::from_slice(&[0x33; 32]).unwrap()
}
fn valid() -> Value {
    json!({"id":-1,"method":"public/get-tickers","code":0,"result":{"data":[
        {"i":"BTC_USDT","a":"100.01","b":"100.00","k":"100.02","t":NOW-100,"v":"123"}
    ]}})
}
fn parse(value: &Value) -> Result<OracleTranscript, String> {
    parse_ticker_response(
        &serde_json::to_vec(value).unwrap(),
        "BTC_USDT",
        NOW,
        0,
        &key(),
    )
}

#[test]
fn exact_instrument_and_original_signed_fields_round_trip() {
    let t = parse(&valid()).unwrap();
    let expected =
        transcript_from_ticker("100.01", "100.00", "100.02", NOW - 100, 0, &key()).unwrap();
    assert_eq!(t, expected);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = crate::signer_address(&key());
    assert_eq!(t.validate(&market, NOW), Ok(t.price));
}

#[test]
fn stale_source_time_remains_stale_instead_of_being_repaired() {
    let mut value = valid();
    value["result"]["data"][0]["t"] = json!(1);
    let t = parse(&value).unwrap();
    assert_eq!(t.publish_time_ms, 1);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = crate::signer_address(&key());
    assert!(t.validate(&market, NOW).is_err());
}

#[test]
fn invalid_status_method_count_or_instrument_is_refused() {
    for code in [
        json!(1),
        json!(-1),
        json!("0"),
        json!(0.0),
        json!(null),
        json!(false),
    ] {
        let mut v = valid();
        v["code"] = code;
        assert!(parse(&v).is_err());
    }
    let mut v = valid();
    v["method"] = json!("public/get-candlestick");
    assert!(parse(&v).is_err());
    let mut v = valid();
    v.as_object_mut().unwrap().remove("method");
    assert!(parse(&v).is_err());
    let mut v = valid();
    v["result"]["data"][0]["i"] = json!("ETH_USDT");
    assert!(parse(&v).is_err());
    let mut v = valid();
    v["result"]["data"] = json!([]);
    assert!(parse(&v).is_err());
    let mut v = valid();
    let row = v["result"]["data"][0].clone();
    v["result"]["data"] = json!([row, row]);
    assert!(parse(&v).is_err());
}

#[test]
fn every_critical_field_is_required_and_typed() {
    for field in ["a", "b", "k", "t", "i"] {
        let mut v = valid();
        v["result"]["data"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(parse(&v).is_err());
        for wrong in [json!(null), json!(true), json!({}), json!([])] {
            let mut v = valid();
            v["result"]["data"][0][field] = wrong;
            assert!(parse(&v).is_err());
        }
    }
    for wrong in [
        json!(0),
        json!(NOW + 1),
        json!(-1),
        json!(1.1),
        json!("999900"),
        json!(u64::MAX),
    ] {
        let mut v = valid();
        v["result"]["data"][0]["t"] = wrong;
        assert!(parse(&v).is_err());
    }
    for field in ["a", "b", "k"] {
        for wrong in [
            json!(100),
            json!(""),
            json!("0"),
            json!("--100"),
            json!("NaN"),
            json!("1e2"),
        ] {
            let mut v = valid();
            v["result"]["data"][0][field] = wrong;
            assert!(parse(&v).is_err());
        }
    }
}

#[test]
fn duplicate_critical_keys_including_escaped_keys_are_rejected() {
    let source = serde_json::to_string(&valid()).unwrap();
    for (old, new) in [
        ("\"code\":0", "\"code\":0,\"code\":0"),
        (
            "\"method\":\"public/get-tickers\"",
            "\"method\":\"public/get-tickers\",\"method\":\"public/get-tickers\"",
        ),
        ("\"result\":", "\"result\":{},\"result\":"),
        ("\"data\":", "\"data\":[],\"data\":"),
        (
            "\"i\":\"BTC_USDT\"",
            "\"i\":\"BTC_USDT\",\"\\u0069\":\"BTC_USDT\"",
        ),
        ("\"a\":\"100.01\"", "\"a\":\"100.01\",\"a\":\"100.01\""),
        ("\"b\":\"100.00\"", "\"b\":\"100.00\",\"b\":\"100.00\""),
        ("\"k\":\"100.02\"", "\"k\":\"100.02\",\"k\":\"100.02\""),
        ("\"t\":999900", "\"t\":999900,\"t\":999900"),
    ] {
        assert!(source.contains(old));
        let duplicated = source.replacen(old, new, 1);
        assert!(parse_ticker_response(duplicated.as_bytes(), "BTC_USDT", NOW, 0, &key()).is_err());
    }
}

#[test]
fn trailing_nonfinite_oversized_and_wrong_instrument_arguments_fail_safely() {
    let source = serde_json::to_vec(&valid()).unwrap();
    let mut trailing = source.clone();
    trailing.extend_from_slice(b"{}");
    assert!(parse_ticker_response(&trailing, "BTC_USDT", NOW, 0, &key()).is_err());
    let mut over = source.clone();
    over.resize(TICKER_LIMIT + 1, b' ');
    assert!(parse_ticker_response(&over, "BTC_USDT", NOW, 0, &key()).is_err());
    for bad in [
        b"NaN".as_slice(),
        b"Infinity",
        b"-Infinity",
        b"private-sentinel",
        b"\xff",
    ] {
        let error = parse_ticker_response(bad, "BTC_USDT", NOW, 0, &key()).unwrap_err();
        assert!(!error.contains("private-sentinel"));
    }
    for name in [
        "",
        "BTC_USDT&evil=1",
        "https://127.0.0.1",
        "BTC/USDT",
        "btc_usdt",
        "BTC_é",
    ] {
        assert!(parse_ticker_response(&source, name, NOW, 0, &key()).is_err());
    }
}

#[test]
fn request_receipt_clock_is_checked_and_accounts_for_elapsed_io() {
    assert_eq!(
        received_time(1_000, Duration::from_millis(400)).unwrap(),
        1_400
    );
    assert!(received_time(0, Duration::ZERO).is_err());
    assert!(received_time(u64::MAX, Duration::from_millis(1)).is_err());
    let mut v = valid();
    v["result"]["data"][0]["t"] = json!(NOW + 200);
    let body = serde_json::to_vec(&v).unwrap();
    assert!(parse_ticker_response(&body, "BTC_USDT", NOW, 0, &key()).is_err());
    let received = received_time(NOW, Duration::from_millis(300)).unwrap();
    assert_eq!(
        parse_ticker_response(&body, "BTC_USDT", received, 0, &key())
            .unwrap()
            .publish_time_ms,
        NOW + 200
    );
}

fn serve(bytes: Vec<u8>) -> (String, thread::JoinHandle<()>) {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/ticker", socket.local_addr().unwrap());
    let task = thread::spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut header = Vec::new();
        let mut byte = [0];
        while !header.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap_or(0) == 0 {
                return;
            }
            header.push(byte[0]);
            assert!(header.len() < 8192);
        }
        let _ = stream.write_all(&bytes);
    });
    (url, task)
}
fn wire(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut value = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{extra}\r\n").into_bytes();
    value.extend_from_slice(body);
    value
}
fn read_from_server(response: Vec<u8>, limit: usize) -> Result<Vec<u8>, String> {
    let (url, task) = serve(response);
    let result = read_body(agent(Duration::from_secs(2)).get(&url), limit);
    task.join().unwrap();
    result
}

#[test]
fn real_http_reads_a_healthy_body_and_parses_its_identity() {
    let body = serde_json::to_vec(&valid()).unwrap();
    let response = wire(
        "200 OK",
        &format!("Content-Length: {}\r\n", body.len()),
        &body,
    );
    let received = read_from_server(response, TICKER_LIMIT).unwrap();
    assert_eq!(received, body);
    assert!(parse_ticker_response(&received, "BTC_USDT", NOW, 0, &key()).is_ok());
}

#[test]
fn real_http_bounds_declared_chunked_and_eof_delimited_bodies() {
    let huge = vec![b' '; TICKER_LIMIT + 1];
    assert!(read_from_server(
        wire(
            "200 OK",
            &format!("Content-Length: {}\r\n", huge.len()),
            &huge
        ),
        TICKER_LIMIT
    )
    .is_err());
    assert!(read_from_server(wire("200 OK", "", &huge), TICKER_LIMIT).is_err());
    let mut chunked = format!("{:x}\r\n", huge.len()).into_bytes();
    chunked.extend_from_slice(&huge);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    assert!(read_from_server(
        wire("200 OK", "Transfer-Encoding: chunked\r\n", &chunked),
        TICKER_LIMIT
    )
    .is_err());
    let exact = vec![b' '; TICKER_LIMIT];
    assert_eq!(
        read_from_server(wire("200 OK", "", &exact), TICKER_LIMIT)
            .unwrap()
            .len(),
        TICKER_LIMIT
    );
}

#[test]
fn real_http_redirect_is_rejected_without_contacting_destination() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let reply = wire(
        "302 Found",
        &format!(
            "Location: http://{}/should-not-contact\r\nContent-Length: 0\r\n",
            target.local_addr().unwrap()
        ),
        b"",
    );
    assert!(read_from_server(reply, TICKER_LIMIT).is_err());
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn real_http_error_and_truncated_body_never_echo_provider_payload() {
    let error = read_from_server(
        wire(
            "500 Internal Server Error",
            "Content-Length: 16\r\n",
            b"private-sentinel",
        ),
        TICKER_LIMIT,
    )
    .unwrap_err();
    assert!(!error.contains("private-sentinel"));
    assert!(read_from_server(
        wire("200 OK", "Content-Length: 100\r\n", b"{}"),
        TICKER_LIMIT
    )
    .is_err());
}

#[test]
fn real_http_stalled_body_reaches_overall_timeout() {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/ticker", socket.local_addr().unwrap());
    let (release, wait) = mpsc::channel();
    let task = thread::spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut header = Vec::new();
        let mut byte = [0];
        while !header.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap_or(0) == 0 {
                return;
            }
            header.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
            .unwrap();
        let _ = wait.recv_timeout(Duration::from_secs(3));
    });
    let start = Instant::now();
    let result = read_body(agent(Duration::from_millis(150)).get(&url), TICKER_LIMIT);
    release.send(()).unwrap();
    task.join().unwrap();
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
}
