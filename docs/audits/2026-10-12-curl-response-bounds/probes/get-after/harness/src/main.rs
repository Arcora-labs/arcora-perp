#[path="/Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/crates/service-transport/curl.rs"] mod curl_transport;
fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    http_get_json_command(url, std::process::Command::new("curl"))
}
fn http_get_json_command(
    url: &str,
    mut command: std::process::Command,
) -> Result<serde_json::Value, String> {
    command.args([
        "-q",
        "-s",
        "-S",
        "--fail",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--",
        url,
    ]);
    let out = curl_transport::run(
        command,
        None,
        curl_transport::Limits {
            stdout: curl_transport::MAX_GET_RESPONSE_BYTES,
            stderr: curl_transport::MAX_STDERR_BYTES,
            timeout: std::time::Duration::from_secs(35),
        },
    )
    .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("attestation HTTP transport exit {}", out.status));
    }
    serde_json::from_slice(&out.stdout).map_err(|_| "invalid attestation JSON response".into())
}
use std::{io::{Read,Write},net::TcpListener,time::Instant};
fn payload(len:usize)->Vec<u8>{ let mut b=b"{\"padding\":\"".to_vec(); b.resize(len-2,b'x'); b.extend_from_slice(b"\"}"); b }
fn main(){
 let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let addr=listener.local_addr().unwrap();
 let peer=std::thread::spawn(move||{
  for size in [1024usize,1048576,1048577,33554432]{
   let(mut stream,peer)=listener.accept().unwrap();assert!(peer.ip().is_loopback());
   stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
   let mut req=Vec::new();let mut byte=[0u8;1];while !req.ends_with(b"\r\n\r\n"){stream.read_exact(&mut byte).unwrap();req.push(byte[0]);assert!(req.len()<4096);}
   let b=payload(size);let header=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",b.len());stream.write_all(header.as_bytes()).unwrap();let _=stream.write_all(&b);
  }
 });
 for size in [1024usize,1048576,1048577,33554432]{
  let start=Instant::now();let r=http_get_json(&format!("http://{addr}/fixture/{size}"));
  if size<=1048576{let v=r.unwrap();assert_eq!(v["padding"].as_str().unwrap().len(),size-14);println!("{}",serde_json::json!({"bytes":size,"accepted":true,"elapsed_ms":start.elapsed().as_millis()}));}
  else{assert_eq!(r.unwrap_err(),"HTTP response exceeds byte limit");println!("{}",serde_json::json!({"bytes":size,"accepted":false,"error":"byte limit","elapsed_ms":start.elapsed().as_millis()}));}
 }
 peer.join().unwrap();println!("{}",serde_json::json!({"owned_connections":4,"peer_joined":true,"scope":"GET transport only; no handshake/attestation/proof"}));
}
