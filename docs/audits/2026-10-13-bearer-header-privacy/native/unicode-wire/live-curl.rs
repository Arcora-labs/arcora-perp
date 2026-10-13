//! Bounded capture of the direct curl child used by both legacy services.
//! Readers run together with the stdin writer; a pipe limit, I/O error or
//! supervisor deadline stops and reaps curl before joining the pipe workers.
//! Peer bodies and stderr never enter transport diagnostics. This supervises
//! the direct curl process, not arbitrary programs with descendant processes.
use std::{
    io::{Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

pub(crate) const MAX_GET_RESPONSE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_STDERR_BYTES: usize = 16 * 1024;
/// Shared /prove JSON ceiling. A configured peer may admit a smaller body.
/// This bounds input bytes, not prior allocations or proving memory.
pub(crate) const MAX_PROVE_REQUEST_BODY_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) stdout: usize,
    pub(crate) stderr: usize,
    pub(crate) timeout: Duration,
}

pub(crate) struct Captured {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Configuration,
    Endpoint,
    RequestBodyLimit,
    Spawn,
    Read,
    Write,
    StdoutLimit,
    StderrLimit,
    Deadline,
    Wait,
    Worker,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid HTTP transport limits",
            Self::Endpoint => "invalid HTTP service base URL",
            Self::RequestBodyLimit => "HTTP request exceeds byte limit",
            Self::Spawn => "HTTP transport could not start",
            Self::Read => "HTTP transport pipe read failed",
            Self::Write => "HTTP transport request write failed",
            Self::StdoutLimit => "HTTP response exceeds byte limit",
            Self::StderrLimit => "HTTP transport diagnostics exceed byte limit",
            Self::Deadline => "HTTP transport supervisor deadline exceeded",
            Self::Wait => "HTTP transport wait failed",
            Self::Worker => "HTTP transport pipe worker failed",
        })
    }
}

/// Append a trusted service path (currently /attest or /prove) to the configured
/// base. A query or fragment would swallow the appended path in curl. Refuse
/// those raw delimiters before any parse/trim; encoded path bytes stay literal.
/// This preserves the existing join for other bases, not a general URL parser.
pub(crate) fn service_endpoint(base: &str, service_path: &str) -> Result<String, Error> {
    if base.bytes().any(|byte| matches!(byte, b'?' | b'#')) {
        return Err(Error::Endpoint);
    }
    Ok(format!("{}{}", base.trim_end_matches('/'), service_path))
}

pub(crate) fn check_request_body_bytes(bytes: usize, limit: usize) -> Result<(), Error> {
    if limit == 0 {
        return Err(Error::Configuration);
    }
    if bytes > limit {
        return Err(Error::RequestBodyLimit);
    }
    Ok(())
}

fn bounded_read(mut pipe: impl Read, limit: usize, overflow: Error) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = match pipe.read(&mut buffer) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Read),
            Ok(0) => return Ok(bytes),
            Ok(n) => n,
        };
        if n > limit - bytes.len() {
            return Err(overflow);
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
}

struct Reap {
    child: Child,
    reaped: bool,
}
impl Reap {
    fn stop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            self.reaped = self.child.wait().is_ok();
        }
    }
}
impl Drop for Reap {
    fn drop(&mut self) {
        self.stop();
    }
}

enum Event {
    Stdout(Vec<u8>),
    Complete,
    Failed(Error),
}

pub(crate) fn run(
    mut command: Command,
    input: Option<&[u8]>,
    limits: Limits,
) -> Result<Captured, Error> {
    let deadline = Instant::now()
        .checked_add(limits.timeout)
        .filter(|_| !limits.timeout.is_zero() && limits.stdout > 0 && limits.stderr > 0)
        .ok_or(Error::Configuration)?;
    if let Some(bytes) = input {
        check_request_body_bytes(bytes.len(), MAX_PROVE_REQUEST_BODY_BYTES)?;
    }
    let child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| Error::Spawn)?;
    std::thread::scope(|scope| {
        // The guard lives inside the scope: even an unwind stops curl before
        // thread::scope implicitly joins already-started pipe workers.
        let mut owned = Reap {
            child,
            reaped: false,
        };
        let stdout = owned.child.stdout.take().ok_or(Error::Worker)?;
        let stderr = owned.child.stderr.take().ok_or(Error::Worker)?;
        let stdin = owned.child.stdin.take();
        if input.is_some() && stdin.is_none() {
            return Err(Error::Worker);
        }
        let (tx, rx) = mpsc::channel();
        let mut workers = Vec::new();
        let out_tx = tx.clone();
        let worker = std::thread::Builder::new().spawn_scoped(scope, move || {
            let event = match bounded_read(stdout, limits.stdout, Error::StdoutLimit) {
                Ok(bytes) => Event::Stdout(bytes),
                Err(e) => Event::Failed(e),
            };
            let _ = out_tx.send(event);
        });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(_) => {
                owned.stop();
                return Err(Error::Worker);
            }
        }
        let err_tx = tx.clone();
        let worker = std::thread::Builder::new().spawn_scoped(scope, move || {
            let event = match bounded_read(stderr, limits.stderr, Error::StderrLimit) {
                Ok(_) => Event::Complete,
                Err(e) => Event::Failed(e),
            };
            let _ = err_tx.send(event);
        });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(_) => {
                owned.stop();
                return Err(Error::Worker);
            }
        }
        let mut pending = 2;
        if let Some(body) = input {
            let mut stdin = stdin.expect("checked piped stdin");
            let in_tx = tx.clone();
            pending += 1;
            let worker = std::thread::Builder::new().spawn_scoped(scope, move || {
                let event = match stdin.write_all(body) {
                    Ok(()) => Event::Complete,
                    Err(_) => Event::Failed(Error::Write),
                };
                drop(stdin);
                let _ = in_tx.send(event);
            });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(_) => {
                    owned.stop();
                    return Err(Error::Worker);
                }
            }
        }
        drop(tx);
        let mut result = (|| {
            let mut stdout = None;
            let mut status = None;
            loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|value| !value.is_zero())
                    .ok_or(Error::Deadline)?;
                if status.is_none() {
                    status = owned.child.try_wait().map_err(|_| Error::Wait)?;
                    owned.reaped = status.is_some();
                }
                if pending == 0 && status.is_some() {
                    if Instant::now() >= deadline {
                        return Err(Error::Deadline);
                    }
                    return Ok(Captured {
                        status: status.ok_or(Error::Wait)?,
                        stdout: stdout.ok_or(Error::Worker)?,
                    });
                }
                if pending == 0 {
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                    continue;
                }
                match rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
                    Ok(Event::Stdout(bytes)) => {
                        stdout = Some(bytes);
                        pending -= 1;
                    }
                    Ok(Event::Complete) => pending -= 1,
                    Ok(Event::Failed(e)) => return Err(e),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Error::Worker),
                }
            }
        })();
        if result.is_err() {
            owned.stop();
        }
        for worker in workers {
            if worker.join().is_err() {
                owned.stop();
                result = Err(Error::Worker);
            }
        }
        result
    })
}

#[cfg(test)]
#[path = "curl_tests.rs"]
mod tests;
