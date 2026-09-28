//! Runtime shutdown is sticky. Stop admitting new work, finish accepted work,
//! then persist the final state. Never cancel a broadcast/proof to report a clean exit.
use tokio::sync::watch;

pub(crate) struct Shutdown {
    state: watch::Sender<bool>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self {
            state: watch::channel(false).0,
        }
    }
}

impl Shutdown {
    pub(crate) fn begin(&self) {
        self.state.send_replace(true);
    }

    pub(crate) fn started(&self) -> bool {
        *self.state.borrow()
    }

    pub(crate) async fn cancelled(&self) {
        let mut state = self.state.subscribe();
        while !*state.borrow_and_update() {
            if state.changed().await.is_err() {
                return;
            }
        }
    }

    pub(crate) async fn next_tick(&self, interval: &mut tokio::time::Interval) -> bool {
        tokio::select! {
            biased;
            _ = self.cancelled() => false,
            _ = interval.tick() => !self.started(),
        }
    }
}

/// Install Unix signal handlers before opening the listener, avoiding a startup
/// window in which an accepted mutation can be terminated by the default handler.
pub(crate) struct Signals {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
}

impl Signals {
    pub(crate) fn new() -> std::io::Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            term: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            #[cfg(unix)]
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
        })
    }

    pub(crate) async fn wait(mut self) {
        #[cfg(unix)]
        tokio::select! {
            _ = self.term.recv() => {},
            _ = self.interrupt.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    }
}
