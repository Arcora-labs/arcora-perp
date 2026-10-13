#![allow(dead_code)]
#[path="live-curl.rs"] mod curl_transport;
mod client {#[path="/Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/target/bearer-argv-validation-20261013/native/live-header.rs"] mod bearer_header;#[derive(Debug)]pub enum ProverClientError{Http(String),Unauthorized}
const STATUS_SENTINEL: &str = "__DPHTTP_STATUS__";
const MAX_PROVE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
fn prove_curl_args(endpoint: &str, timeout_secs: u64, bearer_header: Option<&str>) -> Vec<String> {
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
    if let Some(header_argument) = bearer_header {
        args.push("-H".into());
        args.push(header_argument.into());
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
pub(super) fn http_post_command(
    url: &str,
    body: &str,
    timeout_secs: u64,
    bearer: Option<&str>,
    command: std::process::Command,
) -> Result<String, ProverClientError> {
    http_post_command_with_body_limit(
        url,
        body,
        timeout_secs,
        bearer,
        command,
        crate::curl_transport::MAX_PROVE_REQUEST_BODY_BYTES,
    )
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
    let bearer_header = bearer
        .map(bearer_header::BearerHeader::create)
        .transpose()
        .map_err(|e| ProverClientError::Http(e.into()))?;
    command.args(prove_curl_args(
        &endpoint,
        timeout_secs,
        bearer_header.as_ref().map(|header| header.argument()),
    ));
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
    // Keep the file through run's child supervision and pipe-worker joins. The
    // owner also drops automatically on the preceding transport error.
    drop(bearer_header);
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
}
fn main(){let a:Vec<String>=std::env::args().collect();assert_eq!(a.len(),2);let spec:serde_json::Value=serde_json::from_str(&std::fs::read_to_string(&a[1]).unwrap()).unwrap();let mut command=std::process::Command::new(spec["command"].as_str().unwrap());for key in ["http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"]{command.env_remove(key);}command.env("NO_PROXY","*").env("no_proxy","*");let body=spec["body"].as_str().unwrap();let result=client::http_post_command_with_body_limit(spec["url"].as_str().unwrap(),body,spec["timeout_secs"].as_u64().unwrap(),spec["token"].as_str(),command,spec["body_limit"].as_u64().unwrap() as usize);let returned=match result {Ok(s)=>serde_json::json!({"kind":"OK","body":s,"JSON_accepted":serde_json::from_str::<serde_json::Value>(&s).is_ok()}),Err(e)=>serde_json::json!({"kind":"ERROR","error":format!("{:?}",e)})};println!("{}",serde_json::json!({"returned":returned,"body_bytes":body.len(),"owned_process_TMPDIR_only":true}));}
