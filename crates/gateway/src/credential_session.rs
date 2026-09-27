//! Runtime-only account fences. Lock order: credential fence, then Gw.
//! A private send owns a read lease through the bounded transport write; rotation
//! owns the write lease through mutation, durable ACK and response construction.
//! Bytes already handed to TCP before rotation cannot be recalled from the peer.
use super::*;
use std::future::Future;
use tokio::sync::{watch, RwLock};

pub(super) const SEND_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct Control {
    pub(super) fence: Arc<RwLock<()>>,
    pub(super) changed: watch::Sender<u64>,
}
impl Default for Control {
    fn default() -> Self {
        Self {
            fence: Arc::new(RwLock::new(())),
            changed: watch::channel(0).0,
        }
    }
}

pub(super) struct Session {
    key: [u8; 32],
    owner: PubKey,
    owner_hex: String,
    generation: u64,
    control: Arc<Control>,
    changed: watch::Receiver<u64>,
}
impl Session {
    pub(super) fn authenticate(gw: &Gw, key: [u8; 32]) -> Option<Self> {
        let a = gw.accounts.get(&key)?;
        Some(Self {
            key,
            owner: a.wallet.owner,
            owner_hex: hex0x(&a.wallet.owner),
            generation: a.recovery_nonce,
            control: a.credential_control.clone(),
            // Subscribe under Gw: rotation cannot occur between lookup and watch.
            changed: a.credential_control.changed.subscribe(),
        })
    }
    fn valid(&self, gw: &Gw) -> bool {
        gw.accounts.get(&self.key).is_some_and(|a| {
            a.wallet.owner == self.owner
                && a.recovery_nonce == self.generation
                && Arc::ptr_eq(&a.credential_control, &self.control)
        })
    }
}

/// All authenticated writes, including authOk, use this same boundary. The
/// future is polled only after validation and while the account read lease lives.
/// A failed/timed-out write MUST be followed by dropping the socket, never by
/// flushing it again after the lease is released.
pub(super) async fn send_fenced<F, E>(app: &Shared, session: &Session, send: F) -> bool
where
    F: Future<Output = Result<(), E>>,
{
    let mut changed = session.changed.clone();
    if changed.has_changed().unwrap_or(true) {
        return false;
    }
    let operation = async {
        let _lease = tokio::select! {
            biased;
            _ = changed.changed() => return false,
            lease = session.control.fence.read() => lease,
        };
        if !session.valid(&*app.gw.lock().await) {
            return false;
        }
        // No Gw guard survives the condition above. Only this account is fenced.
        send.await.is_ok()
    };
    tokio::time::timeout(SEND_TIMEOUT, operation)
        .await
        .unwrap_or(false)
}

async fn public_send(socket: &mut WebSocket, message: Message) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, socket.send(message)).await,
        Ok(Ok(()))
    )
}

async fn revoked(auth: &mut Option<Session>) {
    match auth {
        Some(session) => {
            let _ = session.changed.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

pub(super) async fn serve(mut socket: WebSocket, app: Shared) {
    let mut ticks = app.tx.subscribe();
    let mut events = app.events_tx.subscribe();
    let mut auth: Option<Session> = None;
    let initial = { serde_json::to_string(&app.gw.lock().await.v1_public_json()).unwrap() };
    if !public_send(&mut socket, Message::Text(initial)).await {
        return;
    }
    loop {
        tokio::select! {
            biased;
            _ = revoked(&mut auth) => {
                // There is no unfinished private write on this path. The watch
                // wakes idle sessions without requiring any market/client event.
                let _ = public_send(&mut socket, Message::Text(
                    serde_json::json!({"type":"error","message":"api key rotated"}).to_string()
                )).await;
                break;
            }
            client = socket.recv() => {
                match client {
                    Some(Ok(Message::Text(text))) => {
                        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { continue; };
                        if value.get("type").and_then(|v| v.as_str()) == Some("auth") {
                            let key = value.get("apiKey").and_then(|v| v.as_str()).and_then(parse_hex32);
                            auth = match key {
                                Some(key) => Session::authenticate(&*app.gw.lock().await, key),
                                None => None,
                            };
                            if let Some(session) = &auth {
                                let reply = serde_json::json!({"type":"authOk","owner":session.owner_hex});
                                if !send_fenced(&app, session, socket.send(Message::Text(reply.to_string()))).await { break; }
                            } else if !public_send(&mut socket, Message::Text(
                                serde_json::json!({"type":"error","message":"unknown api key"}).to_string()
                            )).await { break; }
                        } else if let Some(session) = &auth {
                            if !session.valid(&*app.gw.lock().await) { break; }
                            // /v1/ws has no command/subscription mutation protocol.
                            // Unknown frames stay no-ops; never dispatch them by owner.
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
            tick = ticks.recv() => {
                match tick {
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Ok(_) => {}
                }
                let json = { serde_json::to_string(&app.gw.lock().await.v1_public_json()).unwrap() };
                let ok = if let Some(session) = &auth {
                    send_fenced(&app, session, socket.send(Message::Text(json))).await
                } else {
                    public_send(&mut socket, Message::Text(json)).await
                };
                if !ok { break; }
            }
            event = events.recv() => {
                let json = match event {
                    Ok(json) => json,
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                };
                if let Some(session) = &auth {
                    let mine = serde_json::from_str::<serde_json::Value>(&json).ok()
                        .and_then(|v| v.get("owner").and_then(|v| v.as_str()).map(|o| o == session.owner_hex))
                        .unwrap_or(false);
                    if mine && !send_fenced(&app, session, socket.send(Message::Text(json))).await { break; }
                }
            }
        }
    }
    // In particular, never send a Close frame after a timed-out private send:
    // that could flush its buffered payload outside the credential fence.
}
