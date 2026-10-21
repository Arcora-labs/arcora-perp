//! Redacted, best-effort operational notifications. Application state and durable
//! ACK decisions never depend on delivery. Episode state is runtime-only; logs are
//! always emitted, while at most one bounded worker delivers optional HTTP alerts,
//! retrying each event a bounded number of times (`DELIVERY_RETRY`).
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
    ArchivePressure,
    /// The bond is below its target and could not be topped up, or top-ups are
    /// paused after a slash an operator has not acknowledged yet.
    BondShortfall,
    /// An open inclusion challenge names an order no settled batch can prove.
    UnanswerableChallenge,
    /// The open-challenge set could not be read for several ticks in a row.
    ChallengeDiscoveryFailed,
    /// The clock anchor of the current batch is older than `anchorTimeoutMs`: its
    /// proof has not settled, and the window needs operator recovery.
    StaleAnchor,
    /// Half of the settlement's liveness window has passed without progress.
    LivenessLow,
    /// Finalized block headers have not re-hashed for a long stretch, so expired
    /// deposit permits are not being removed. Intake and settlement continue; the
    /// header format probably gained a field this gateway does not know.
    PermitGcStalled,
    /// The engine is in close-only (a liquidation's bad debt outran insurance, the
    /// treasury and auto-deleverage) while the L1 settlement is not. No deposit
    /// permit is issued and no deposit is credited; governance should call
    /// `enterCloseOnly` so the wind-down can start.
    EngineCloseOnly,
    /// The provable-history admission cap is reached: new deposit permits and
    /// registrations are refused. Exits keep working.
    AdmissionCapReached,
    /// At boot the withdrawal-leaf counter was at or behind the engine's last
    /// withdrawal nonce and was moved forward. The restored snapshot's counter
    /// lagged its engine state; find out which snapshot was restored.
    WithdrawNonceRepaired,
    /// A deposit landed on L1 under a permit and is not credited because the hard
    /// admission cap is reached. Ingestion stops at it, so it is the oldest
    /// unconsumed deposit, and once it is older than the settlement's
    /// `livenessTimeoutBlocks` anyone can put the settlement in close-only.
    DepositBlockedAtCap,
    /// A sealed phase-0 window whose clock intent can never settle was voided: the
    /// state returned to the window's pre-state, its fills and withdrawals were
    /// undone, its orders were published as cancelled and its deposits were
    /// restored for re-ingestion. Recovered once the next window settles. Not
    /// persisted: a restart clears it.
    WindowVoided,
    /// The settle loop is recovering a clock-bound window and needs the operator,
    /// or is running out of time: another anchor holds the batch, the settle keeps
    /// failing against its own anchor, a deposit halt blocks the retry, repeated
    /// voids stopped the loop, or the recovery has lasted long or used up half of
    /// the close-only budget. Recovered when the recovery resolves.
    ClockRecoveryBlocked,
}

#[cfg(test)]
impl AlertKind {
    /// Every kind, in declaration order.
    pub const ALL: [AlertKind; 16] = [
        AlertKind::SettlementHeld,
        AlertKind::PersistenceFailed,
        AlertKind::DepositHalted,
        AlertKind::ArchivePressure,
        AlertKind::BondShortfall,
        AlertKind::UnanswerableChallenge,
        AlertKind::ChallengeDiscoveryFailed,
        AlertKind::StaleAnchor,
        AlertKind::LivenessLow,
        AlertKind::PermitGcStalled,
        AlertKind::EngineCloseOnly,
        AlertKind::AdmissionCapReached,
        AlertKind::WithdrawNonceRepaired,
        AlertKind::DepositBlockedAtCap,
        AlertKind::WindowVoided,
        AlertKind::ClockRecoveryBlocked,
    ];
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

    /// Same body every attempt; nothing about the failure is fed back into it.
    fn deliver_with_retry(&self, body: &str, retry: RetryPolicy) -> bool {
        for attempt in 0..retry.attempts {
            if self.deliver(body) {
                return true;
            }
            if attempt + 1 < retry.attempts {
                std::thread::sleep(retry.backoff * 2u32.pow(attempt));
            }
        }
        false
    }
}

/// Bounded redelivery of one event: `attempts` tries, waiting `backoff`, then
/// twice that, between them. Delivery stays best effort after the last try.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryPolicy {
    pub(crate) attempts: u32,
    pub(crate) backoff: std::time::Duration,
}

pub(crate) const DELIVERY_RETRY: RetryPolicy = RetryPolicy {
    attempts: 3,
    backoff: std::time::Duration::from_secs(1),
};

enum Work {
    Deliver(String),
    #[cfg(test)]
    Barrier(mpsc::Sender<()>),
}
#[derive(Default)]
struct Episodes {
    // (last episode number, currently active). Only the closed enum values can
    // enter this map; untrusted errors cannot grow this state.
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
        Self::configured_with(local, topic, DELIVERY_RETRY)
    }

    fn configured_with(
        local: Option<&str>,
        topic: Option<&str>,
        retry: RetryPolicy,
    ) -> Result<Self, &'static str> {
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
                            if !target.deliver_with_retry(&body, retry) {
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

    /// The kinds currently active, for the health surface.
    pub fn active(&self) -> Vec<AlertKind> {
        let episodes = self.0.lock().unwrap_or_else(|p| p.into_inner());
        episodes
            .state
            .iter()
            .filter(|(_, (_, active))| *active)
            .map(|(kind, _)| *kind)
            .collect()
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
