#![allow(dead_code)]
#[path="base-curl.rs"] mod curl_transport;
mod gateway_get { use crate::curl_transport;
fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    http_get_json_command(url, std::process::Command::new("curl"))
}
fn http_get_json_command(
    url: &str,
    mut command: std::process::Command,
) -> Result<serde_json::Value, String> {
    command.args([
        "-q",
        // A configured attestation URL names one HTTP(S) transfer. Curl's
        // default brace/range expansion can otherwise contact multiple paths.
        "--globoff",
        "--proto",
        "=http,https",
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
pub(super) fn call(u:&str,c:std::process::Command)->Result<serde_json::Value,String>{http_get_json_command(u,c)}
}
mod prover_get { use crate::curl_transport;
fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    http_get_json_command(url, std::process::Command::new("curl"))
}
fn http_get_json_command(
    url: &str,
    mut command: std::process::Command,
) -> Result<serde_json::Value, String> {
    command.args([
        "-q",
        // A configured attestation URL names one HTTP(S) transfer. Curl's
        // default brace/range expansion can otherwise contact multiple paths.
        "--globoff",
        "--proto",
        "=http,https",
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
pub(super) fn call(u:&str,c:std::process::Command)->Result<serde_json::Value,String>{http_get_json_command(u,c)}
}
mod prover_client { #[derive(Debug)] pub enum ProverClientError {Http(String),Unauthorized}
const STATUS_SENTINEL: &str = "__DPHTTP_STATUS__";
const MAX_PROVE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
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
fn http_post(
    url: &str,
    body: &str,
    timeout_secs: u64,
    bearer: Option<&str>,
) -> Result<String, ProverClientError> {
    http_post_command(
        url,
        body,
        timeout_secs,
        bearer,
        std::process::Command::new("curl"),
    )
}
pub(super) fn http_post_command(
    url: &str,
    body: &str,
    timeout_secs: u64,
    bearer: Option<&str>,
    mut command: std::process::Command,
) -> Result<String, ProverClientError> {
    use crate::curl_transport::{self, Limits};
    use std::time::Duration;
    let deadline = timeout_secs
        .checked_add(5)
        .filter(|_| timeout_secs > 0)
        .ok_or_else(|| ProverClientError::Http("invalid HTTP transport timeout".into()))?;
    let endpoint = format!("{}/prove", url.trim_end_matches('/'));
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
}
fn main(){let a:Vec<String>=std::env::args().collect();assert_eq!(a.len(),4);let mut c=std::process::Command::new(&a[3]);for key in ["http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"]{c.env_remove(key);}c.env("NO_PROXY","*").env("no_proxy","*");let result=match a[1].as_str(){"post"=>{let body="x".repeat(160*1024);match prover_client::http_post_command(&a[2],&body,5,Some("synthetic-bearer"),c){Ok(s)=>serde_json::json!({"kind":"OK","json_parser_accepted":serde_json::from_str::<serde_json::Value>(&s).is_ok(),"body":s}),Err(e)=>serde_json::json!({"kind":"ERROR","error":format!("{:?}",e)})}},"gateway-get"=>match gateway_get::call(&a[2],c){Ok(v)=>serde_json::json!({"kind":"OK","value":v}),Err(e)=>serde_json::json!({"kind":"ERROR","error":e})},"prover-get"=>match prover_get::call(&a[2],c){Ok(v)=>serde_json::json!({"kind":"OK","value":v}),Err(e)=>serde_json::json!({"kind":"ERROR","error":e})},_=>panic!("unknown owned mode")};println!("{}",result);}
