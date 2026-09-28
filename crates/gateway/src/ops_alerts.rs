//! Redacted, best-effort operational notifications. Application state and durable
//! ACK decisions never depend on delivery. Episode state is runtime-only; logs are
//! always emitted, while at most one bounded worker delivers optional HTTP alerts.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    sync::{mpsc, Arc, Mutex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    SettlementHeld,
    PersistenceFailed,
    DepositHalted,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Transition {
    Active,
    Recovered,
}

// Deliberately no arbitrary message/error/URL/account fields. Redaction is a
// construction guarantee, rather than regex filtering after secrets were copied.
#[derive(Debug, Serialize)]
struct Event {
    schema: &'static str,
    event: AlertKind,
    transition: Transition,
    episode: u64,
}

#[derive(Clone)]
enum Target {
    Loopback(String),
    Ntfy(String),
}
impl Target {
    fn parse(local: Option<&str>, topic: Option<&str>) -> Result<Option<Self>, &'static str> {
        let local = local.filter(|s| !s.is_empty());
        let topic = topic.filter(|s| !s.is_empty());
        match (local, topic) {
            (Some(_), Some(_)) => Err("configure only one operational alert transport"),
            (Some(url), None) => {
                // No DNS, userinfo, query/fragment, path rewriting or redirects.
                // The collector cannot be redirected to an external recipient.
                let port = url
                    .strip_prefix("http://127.0.0.1:")
                    .or_else(|| url.strip_prefix("http://[::1]:"))
                    .and_then(|s| s.strip_suffix("/alerts"))
                    .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|s| s.parse::<u16>().ok())
                    .filter(|p| *p != 0)
                    .ok_or("FIN_ALERT_LOCAL_URL must be a literal loopback HTTP endpoint ending /alerts")?;
                let _ = port;
                Ok(Some(Self::Loopback(url.to_owned())))
            }
            (None, Some(topic)) => {
                if topic.len() > 128
                    || !topic
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                {
                    return Err("FIN_ALERT_NTFY_TOPIC must contain only letters, digits, dash or underscore (max 128)");
                }
                Ok(Some(Self::Ntfy(format!("https://ntfy.sh/{topic}"))))
            }
            (None, None) => Ok(None),
        }
    }

    fn deliver(&self, body: &str) -> bool {
        let (url, protocol) = match self {
            Self::Loopback(url) => (url, "=http"),
            Self::Ntfy(url) => (url, "=https"),
        };
        let mut command = Command::new("curl");
        command.args([
            "-q", // Do not read ~/.curlrc (which could add redirects or proxies).
            "--silent",
            "--fail",
            "--globoff",
            "--connect-timeout",
            "1",
            "--max-time",
            "2",
            "--max-redirs",
            "0",
            "--proto",
            protocol,
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--request",
            "POST",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
        ]);
        if matches!(self, Self::Loopback(_)) {
            command.args(["--noproxy", "*"]);
        }
        let Ok(mut child) = command
            .arg(url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        let written = child
            .stdin
            .take()
            .is_some_and(|mut input| input.write_all(body.as_bytes()).is_ok());
        child.wait_with_output().is_ok_and(|output| {
            let status = std::str::from_utf8(&output.stdout)
                .ok()
                .and_then(|s| s.parse::<u16>().ok());
            written && output.status.success() && status.is_some_and(|s| (200..300).contains(&s))
        })
    }
}

enum Work {
    Deliver(String),
    #[cfg(test)]
    Barrier(mpsc::Sender<()>),
}
#[derive(Default)]
struct Episodes {
    // (last episode number, currently active). Only the three closed enum values
    // can enter this map; untrusted errors cannot grow this state.
    state: BTreeMap<AlertKind, (u64, bool)>,
    delivery: Option<mpsc::SyncSender<Work>>,
}

/// Clones share both episode tracking and the single delivery worker. Default is
/// log-only and has no environment reads or thread side effects, including restore.
#[derive(Clone, Default)]
pub struct OpsAlerts(Arc<Mutex<Episodes>>);

impl OpsAlerts {
    pub fn from_env() -> Result<Self, &'static str> {
        let local = std::env::var("FIN_ALERT_LOCAL_URL")
            .map(Some)
            .or_else(|e| match e {
                std::env::VarError::NotPresent => Ok(None),
                _ => Err("FIN_ALERT_LOCAL_URL is not valid text"),
            })?;
        let topic = std::env::var("FIN_ALERT_NTFY_TOPIC")
            .map(Some)
            .or_else(|e| match e {
                std::env::VarError::NotPresent => Ok(None),
                _ => Err("FIN_ALERT_NTFY_TOPIC is not valid text"),
            })?;
        Self::configured(local.as_deref(), topic.as_deref())
    }

    fn configured(local: Option<&str>, topic: Option<&str>) -> Result<Self, &'static str> {
        let target = Target::parse(local, topic)?;
        let Some(target) = target else {
            return Ok(Self::default());
        };
        let (tx, rx) = mpsc::sync_channel(32);
        std::thread::Builder::new()
            .name("ops-alert-delivery".into())
            .spawn(move || {
                while let Ok(work) = rx.recv() {
                    match work {
                        Work::Deliver(body) => {
                            if !target.deliver(&body) {
                                eprintln!("[ops-alert-delivery] failed; structured event remains in local log");
                            }
                        }
                        #[cfg(test)]
                        Work::Barrier(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })
            .map_err(|_| "could not start operational alert delivery worker")?;
        Ok(Self(Arc::new(Mutex::new(Episodes {
            state: BTreeMap::new(),
            delivery: Some(tx),
        }))))
    }

    pub fn activate(&self, kind: AlertKind) {
        self.transition(kind, true);
    }

    pub fn recover(&self, kind: AlertKind) {
        self.transition(kind, false);
    }

    fn transition(&self, kind: AlertKind, active: bool) {
        // No payload comes from a panic; preserving the state still permits a
        // best-effort operational log and must never change application outcomes.
        let mut episodes = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let (number, was_active) = episodes.state.entry(kind).or_default();
        if *was_active == active {
            return;
        }
        if active {
            *number = number.saturating_add(1);
        }
        *was_active = active;
        let event = Event {
            schema: "arcora.ops-alert.v1",
            event: kind,
            transition: if active {
                Transition::Active
            } else {
                Transition::Recovered
            },
            episode: *number,
        };
        // A fixed enum-only schema cannot fail JSON serialization.
        let body = serde_json::to_string(&event).expect("fixed operational event schema");
        eprintln!("[ops-alert] {body}");
        if let Some(tx) = &episodes.delivery {
            if tx.try_send(Work::Deliver(body)).is_err() {
                eprintln!(
                    "[ops-alert-delivery] queue unavailable; structured event remains in local log"
                );
            }
        }
    }

    #[cfg(test)]
    fn flush(&self) {
        let tx = self.0.lock().unwrap().delivery.clone();
        if let Some(tx) = tx {
            let (done, wait) = mpsc::channel();
            tx.try_send(Work::Barrier(done))
                .unwrap_or_else(|_| panic!("test alert queue full"));
            wait.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
    }
}

#[cfg(test)]
#[path = "ops_alerts/integration_tests.rs"]
mod integration_tests;
