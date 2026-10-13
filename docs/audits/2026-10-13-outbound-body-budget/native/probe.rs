#![allow(dead_code)]
#[path="live-curl.rs"] mod curl_transport;
mod client { #[derive(Debug)] pub enum ProverClientError {Http(String),Unauthorized}
const STATUS_SENTINEL: &str = "__DPHTTP_STATUS__";
const MAX_PROVE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
fn sealed_request_json_bytes(
    plaintext_bytes: usize,
) -> Result<usize, crate::curl_transport::Error> {
    let mut remaining = plaintext_bytes;
    let mut prefix = 1usize;
    while remaining >= 128 {
        remaining >>= 7;
        prefix += 1;
    }
    let wire_bytes = plaintext_bytes
        .checked_add(prefix)
        .and_then(|bytes| bytes.checked_add(96))
        .ok_or(crate::curl_transport::Error::RequestBodyLimit)?;
    prove_request_json_bytes(wire_bytes)
}
fn prove_request_json_bytes(
    sealed_wire_bytes: usize,
) -> Result<usize, crate::curl_transport::Error> {
    sealed_wire_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(15))
        .ok_or(crate::curl_transport::Error::RequestBodyLimit)
}
fn prove_curl_args(endpoint: &str, timeout_secs: u64, bearer: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "-q".into(),
        // One configured endpoint must not expand into several proof POSTs.
        "--globoff".into(),
        "--proto".into(),
        "=http,https".into(),
        "-s".into(),
        "-S".into(),
        "--connect-timeout".into(),
        "20".into(),
        "--keepalive-time".into(),
        "30".into(),
        "--max-time".into(),
        timeout_secs.to_string(),
        "-X".into(),
        "POST".into(),
        "-H".into(),
        "Content-Type: application/json".into(),
    ];
    if let Some(token) = bearer {
        args.push("-H".into());
        args.push(format!("Authorization: Bearer {token}"));
    }
    // Append the HTTP status after the body under STATUS_SENTINEL (see `split_status`).
    args.push("-w".into());
    args.push(format!("\n{STATUS_SENTINEL}%{{http_code}}"));
    args.push("--data-binary".into());
    args.push("@-".into());
    args.push("--".into());
    args.push(endpoint.into());
    args
}
fn split_status(raw: &str) -> Result<(String, u16), ProverClientError> {
    let marker = format!("\n{STATUS_SENTINEL}");
    let idx = raw
        .rfind(&marker)
        .ok_or_else(|| ProverClientError::Http("curl -w status marker missing".into()))?;
    let body = raw[..idx].to_string();
    let code = raw[idx + marker.len()..].trim();
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProverClientError::Http("invalid HTTP status marker".into()));
    }
    let status = code
        .parse::<u16>()
        .map_err(|_| ProverClientError::Http("invalid HTTP status marker".into()))?;
    if !(100..=599).contains(&status) {
        return Err(ProverClientError::Http("invalid HTTP status marker".into()));
    }
    Ok((body, status))
}
pub(super) fn http_post_command_with_body_limit(
    url: &str,
    body: &str,
    timeout_secs: u64,
    bearer: Option<&str>,
    mut command: std::process::Command,
    body_limit: usize,
) -> Result<String, ProverClientError> {
    use crate::curl_transport::{self, Limits};
    use std::time::Duration;
    let deadline = timeout_secs
        .checked_add(5)
        .filter(|_| timeout_secs > 0)
        .ok_or_else(|| ProverClientError::Http("invalid HTTP transport timeout".into()))?;
    let endpoint = curl_transport::service_endpoint(url, "/prove")
        .map_err(|e| ProverClientError::Http(e.to_string()))?;
    curl_transport::check_request_body_bytes(body.len(), body_limit)
        .map_err(|e| ProverClientError::Http(e.to_string()))?;
    command.args(prove_curl_args(&endpoint, timeout_secs, bearer));
    let out = curl_transport::run(
        command,
        Some(body.as_bytes()),
        Limits {
            stdout: MAX_PROVE_RESPONSE_BYTES + STATUS_SENTINEL.len() + 4,
            stderr: curl_transport::MAX_STDERR_BYTES,
            timeout: Duration::from_secs(deadline),
        },
    )
    .map_err(|e| ProverClientError::Http(e.to_string()))?;
    // Without `--fail`, a non-zero curl exit now means a TRANSPORT failure (connect
    // timeout, DNS, tunnel down) — the HTTP status itself rides the `-w` sentinel.
    if !out.status.success() {
        return Err(ProverClientError::Http(format!(
            "prover HTTP transport exit {}",
            out.status,
        )));
    }
    let raw = std::str::from_utf8(&out.stdout)
        .map_err(|_| ProverClientError::Http("invalid UTF-8 HTTP response".into()))?;
    let (resp_body, status) = split_status(raw)?;
    if resp_body.len() > MAX_PROVE_RESPONSE_BYTES {
        return Err(ProverClientError::Http(
            "HTTP response exceeds byte limit".into(),
        ));
    }
    match status {
        200..=299 => Ok(resp_body),
        // SEC-020 Task 5: the /prove gate rejected the bearer — surface as a typed
        // 401 so `prove` can re-handshake once and retry (fail-closed on a second 401).
        401 => Err(ProverClientError::Unauthorized),
        s => Err(ProverClientError::Http(format!("prover /prove HTTP {s}"))),
    }
}
pub(super) fn early_cut(p:usize,body_limit:usize)->serde_json::Value {let mut phases=vec!["public_plaintext_allocated"];let bytes=vec![0x35u8;p];let result=(||->Result<usize,ProverClientError>{
    let predicted_body_bytes = sealed_request_json_bytes(bytes.len())
        .map_err(|e| ProverClientError::Http(e.to_string()))?;
    crate::curl_transport::check_request_body_bytes(predicted_body_bytes, body_limit)
        .map_err(|e| ProverClientError::Http(e.to_string()))?;
phases.push("continuation_sentinel_after_early_guard");Ok(predicted_body_bytes)})();serde_json::json!({"kind":"isolated_early_guard_cut","plaintext_bytes":p,"budget":body_limit,"phases":phases,"result":format!("{:?}",result),"NOT_full_keyrelease_or_sealing_execution":true})}
pub(super) fn actual_cut(n:usize,body_limit:usize)->serde_json::Value {let mut phases=vec!["public_wire_buffer_available"];let out=vec![0x22u8;n];let result=(||->Result<usize,ProverClientError>{
    let actual_body_bytes =
        prove_request_json_bytes(out.len()).map_err(|e| ProverClientError::Http(e.to_string()))?;
    crate::curl_transport::check_request_body_bytes(actual_body_bytes, body_limit)
        .map_err(|e| ProverClientError::Http(e.to_string()))?;
phases.push("continuation_sentinel_before_hex");Ok(actual_body_bytes)})();serde_json::json!({"kind":"isolated_actual_wire_guard_cut","wire_bytes":n,"budget":body_limit,"phases":phases,"result":format!("{:?}",result),"NOT_real_sealed_container_acceptance":true})}
pub(super) fn pure_sizes()->serde_json::Value {let l=crate::curl_transport::MAX_PROVE_REQUEST_BODY_BYTES;serde_json::json!({"shared_JSON_ceil":l,"max_numeric_boundary":format!("{:?}",crate::curl_transport::check_request_body_bytes(l,l)),"max_numeric_plus1":format!("{:?}",crate::curl_transport::check_request_body_bytes(l+1,l)),"plaintext_usize_MAX_overflow":format!("{:?}",sealed_request_json_bytes(usize::MAX)),"wire_usize_MAX_overflow":format!("{:?}",prove_request_json_bytes(usize::MAX)),"wire_multiplication_edge_overflow":format!("{:?}",prove_request_json_bytes(usize::MAX/2)),"numeric_only_no_largeallocation":true})}
pub(super) fn small_sizes()->serde_json::Value {let mut rows=Vec::new();for p in [0usize,1,127,128,4096,16383,16384]{let ct=vec![0x35u8;p];let shape=(&ct,[0x11u8;32],[0x22u8;32],[0x33u8;32]);let out=postcard::to_allocvec(&shape).unwrap();let exact:prover::SealedWitness=postcard::from_bytes(&out).unwrap();assert_eq!(postcard::to_allocvec(&exact).unwrap(),out);let mut hexed=String::with_capacity(2+out.len()*2);hexed.push_str("0x");for b in &out {hexed.push_str(&format!("{b:02x}"));}let body=serde_json::json!({"sealed":hexed}).to_string();assert_eq!(sealed_request_json_bytes(p).unwrap(),body.len());assert_eq!(prove_request_json_bytes(out.len()).unwrap(),body.len());rows.push(serde_json::json!({"p":p,"wire":out.len(),"JSON":body.len(),"predicted":sealed_request_json_bytes(p).unwrap()}));}serde_json::json!(rows)}
}
fn main(){let a:Vec<String>=std::env::args().collect();if a[1]=="cuts" {println!("{}",serde_json::json!({"pure":client::pure_sizes(),"small_sizes":client::small_sizes(),"early_exact":client::early_cut(128,467),"early_over":client::early_cut(128,466),"actual_exact":client::actual_cut(226,467),"actual_over":client::actual_cut(226,466)}));return;}assert_eq!(a.len(),6);let body=std::fs::read_to_string(&a[3]).unwrap();let mut command=std::process::Command::new(&a[5]);for key in ["http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"]{command.env_remove(key);}command.env("NO_PROXY","*").env("no_proxy","*");let budget=a[4].parse::<usize>().unwrap();let result=client::http_post_command_with_body_limit(&a[2],&body,5,Some("synthetic-bearer"),command,budget);let returned=match result {Ok(s)=>serde_json::json!({"kind":"OK","body":s,"JSON_response_accepted":serde_json::from_str::<serde_json::Value>(&s).is_ok()}),Err(e)=>serde_json::json!({"kind":"ERROR","error":format!("{:?}",e)})};println!("{}",serde_json::json!({"body_bytes":body.len(),"body_chars":body.chars().count(),"budget":budget,"returned":returned}));}
