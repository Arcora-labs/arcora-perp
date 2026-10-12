//! Real curl against owned loopback fixtures; no attestation or proof acceptance.
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
    complete_payload_bytes: usize,
    write_error: Option<String>,
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
        let mut write_error = None;
        let mut complete_payload_bytes = 0usize;
        let mut response_complete = socket.write_all(header.as_bytes()).map_err(|e| { write_error=Some(format!("{:?}",e.kind()));e }).is_ok();
        if response_complete {
            for chunk in payload.chunks(8192) {
                if matches!(framing, Framing::Chunked)
                    && write!(socket, "{:x}\r\n", chunk.len()).map_err(|e| { write_error=Some(format!("{:?}",e.kind()));e }).is_err()
                {
                    response_complete = false;
                    break;
                }
                if socket.write_all(chunk).map_err(|e| { write_error=Some(format!("{:?}",e.kind()));e }).is_err() {
                    response_complete = false;
                    break;
                }
                complete_payload_bytes += chunk.len();
                if matches!(framing, Framing::Chunked) && socket.write_all(b"\r\n").map_err(|e| { write_error=Some(format!("{:?}",e.kind()));e }).is_err() {
                    response_complete = false;
                    break;
                }
            }
            if response_complete && matches!(framing, Framing::Chunked) {
                response_complete = socket.write_all(b"0\r\n\r\n").map_err(|e| { write_error=Some(format!("{:?}",e.kind()));e }).is_ok();
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
            complete_payload_bytes,
            write_error,
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


#[path = "/Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/crates/service-transport/curl.rs"] mod curl_transport;
fn main() {
 let dir=std::path::PathBuf::from(std::env::args_os().nth(1).expect("owned output"));
 for attempt in 0..6 { for mode in 0..2 {
  let len=if mode==0 {1048577usize} else {4194304usize};
  let payload=if mode==0 {json_body(len)} else {vec![b'x';len]};
  let (url,peer)=fixture(200,payload,if mode==0 {Framing::Length} else {Framing::Chunked});
  let error_path=dir.join(format!("curl-{attempt}-{mode}.stderr.log"));
  assert!(!error_path.exists());
  let mut command=curl();command.args(["-q","--stderr"]).arg(&error_path);
  let mut input=None;
  let cap;
  if mode==0 { command.args(["-s","-S","--fail","--connect-timeout","10","--max-time","30","--",&url]);cap=1048576; }
  else { command.args(["-s","-S","--connect-timeout","20","--keepalive-time","30","--max-time","5","-X","POST","-H","Content-Type: application/json","-w","\n__DPHTTP_STATUS__%{http_code}","--data-binary","@-","--",&format!("{url}/prove")]); input=Some(b"{}".as_slice());cap=4194304+21; }
  let start=Instant::now();
  let result=curl_transport::run(command,input,curl_transport::Limits {stdout:cap,stderr:16384,timeout:Duration::from_secs(if mode==0 {35} else {10})});
  let exchange=peer.join().expect("owned peer joined");
  match result {Ok(out)=>println!("attempt={attempt} mode={mode} stdout_bytes={} code={:?} error=none complete={} payload_complete_bytes={} write_error={:?} millis={}",out.stdout.len(),out.status.code(),exchange.response_complete,exchange.complete_payload_bytes,exchange.write_error,start.elapsed().as_millis()),Err(e)=>println!("attempt={attempt} mode={mode} stdout_bytes=none code=none error={e:?} complete={} payload_complete_bytes={} write_error={:?} millis={}",exchange.response_complete,exchange.complete_payload_bytes,exchange.write_error,start.elapsed().as_millis())}
 } }
}
