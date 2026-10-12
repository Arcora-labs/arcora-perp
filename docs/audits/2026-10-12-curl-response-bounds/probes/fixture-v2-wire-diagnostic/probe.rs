use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener},
    process::Command,
    thread::JoinHandle,
    time::{Duration, Instant},
};

fn curl() -> Command {
    let mut command = Command::new("curl");
    for name in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ] {
        command.env_remove(name);
    }
    command.env("NO_PROXY", "*").env("no_proxy", "*");
    command
}

#[derive(Clone, Copy)]
enum Framing {
    Length,
    Chunked,
    Close,
}

struct Exchange {
    request: Vec<u8>,
    response_complete: bool,
}

fn fixture(status: u16, payload: Vec<u8>, framing: Framing) -> (String, JoinHandle<Exchange>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, peer)) => {
                    assert!(peer.ip().is_loopback());
                    break socket;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "owned fixture never contacted");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("owned accept failed: {e}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let header_end = loop {
            let mut bytes = [0u8; 8192];
            let n = socket.read(&mut bytes).unwrap();
            assert!(n > 0);
            request.extend_from_slice(&bytes[..n]);
            assert!(request.len() <= 256 * 1024);
            if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let headers = std::str::from_utf8(&request[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(content_length <= 192 * 1024);
        while request.len() < header_end + content_length {
            let mut bytes = [0u8; 8192];
            let n = socket.read(&mut bytes).unwrap();
            assert!(n > 0);
            request.extend_from_slice(&bytes[..n]);
        }
        let framing_header = match framing {
            Framing::Length => format!("Content-Length: {}\r\n", payload.len()),
            Framing::Chunked => "Transfer-Encoding: chunked\r\n".into(),
            Framing::Close => String::new(),
        };
        let header =
            format!("HTTP/1.1 {status} Fixture\r\n{framing_header}Connection: close\r\n\r\n");
        let mut response_complete = socket.write_all(header.as_bytes()).is_ok();
        if response_complete {
            for chunk in payload.chunks(8192) {
                if matches!(framing, Framing::Chunked)
                    && write!(socket, "{:x}\r\n", chunk.len()).is_err()
                {
                    response_complete = false;
                    break;
                }
                if socket.write_all(chunk).is_err() {
                    response_complete = false;
                    break;
                }
                if matches!(framing, Framing::Chunked) && socket.write_all(b"\r\n").is_err() {
                    response_complete = false;
                    break;
                }
            }
            if response_complete && matches!(framing, Framing::Chunked) {
                response_complete = socket.write_all(b"0\r\n\r\n").is_ok();
            }
        }
        // Finish the response direction before dropping the socket. Wait for
        // client close to avoid cutting short a queued positive response;
        // over-limit clients may reset their own connection.
        let _ = socket.shutdown(Shutdown::Write);
        let mut tail = [0u8; 1];
        let _ = socket.read(&mut tail);
        Exchange {
            request,
            response_complete,
        }
    });
    (url, handle)
}

fn json_body(len: usize) -> Vec<u8> {
    let mut bytes = b"{\"padding\":\"".to_vec();
    bytes.resize(len - 2, b'x');
    bytes.extend_from_slice(b"\"}");
    bytes
}

fn main(){for attempt in 0..6{for mode in [0,1]{let payload=if mode==0{json_body(1048577)}else{vec![b'x';4194304]};let(url,peer)=fixture(200,payload,if mode==0{Framing::Length}else{Framing::Chunked});let mut cmd=curl();cmd.args(["-q","-s","-S","--fail","--max-time","10","--",&url]);let result=cmd.output().unwrap();let exchange=peer.join().unwrap();println!("attempt={} mode={} captured={} code={:?} peer_complete={} diagnostic={}",attempt,mode,result.stdout.len(),result.status.code(),exchange.response_complete,String::from_utf8_lossy(&result.stderr));assert_eq!(result.status.code(),Some(0));}}}