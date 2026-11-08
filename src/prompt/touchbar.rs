//! Bounded presentation-only D-Bus projection. No account names, authentication
//! result, key input or credential channel is exposed to an observer.
use super::{Deadline, Presentation, PromptOperation, PromptPhase, PromptStorage, PromptTarget};
use serde::Serialize;
use std::{
    io,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const PATH: &str = "/cameroncooper/keychain/AuthenticationAgent";
pub const INTERFACE: &str = "cameroncooper.keychain.AuthenticationAgent.TouchBar1";
const MAX_SNAPSHOT: usize = 8192;

/// Internal connection identity is never exported as the presentation ID. It
/// prevents stale events from a rejected/replaced connection reusing a UUID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestKey {
    pub id: Uuid,
    pub connection: Uuid,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Target {
    WebAuthn { rp_id: String },
    Login { website: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Request {
    id: Uuid,
    operation: PromptOperation,
    target: Option<Target>,
    storage: Option<PromptStorage>,
    phase: PromptPhase,
    desktop_visible: bool,
    cancelable: bool,
    expires_at_monotonic_usec: Option<u64>,
    message: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Snapshot {
    version: u32,
    generation: u64,
    request: Option<Request>,
}
#[derive(Clone)]
struct State {
    key: Option<RequestKey>,
    hidden: Option<Request>,
    snapshot: Snapshot,
}
impl Default for State {
    fn default() -> Self {
        Self {
            key: None,
            hidden: None,
            snapshot: Snapshot {
                version: 1,
                generation: 0,
                request: None,
            },
        }
    }
}
impl State {
    fn json(&self) -> io::Result<String> {
        let value = serde_json::to_string(&self.snapshot).map_err(io::Error::other)?;
        if value.len() > MAX_SNAPSHOT {
            return Err(io::Error::other("Touch Bar snapshot exceeds limit"));
        }
        Ok(value)
    }
}
#[derive(Clone)]
pub struct Publication {
    state: Arc<Mutex<State>>,
    wake: mpsc::SyncSender<()>,
}
pub struct Publications {
    state: Arc<Mutex<State>>,
    wake: mpsc::Receiver<()>,
}
pub struct CancelCommand {
    pub key: RequestKey,
    applied: mpsc::SyncSender<()>,
}
impl CancelCommand {
    pub fn applied(self) {
        let _ = self.applied.try_send(());
    }
}
impl Publication {
    pub fn new() -> (Self, Publications) {
        let state = Arc::new(Mutex::new(State::default()));
        let (sender, wake) = mpsc::sync_channel(1);
        (
            Self {
                state: state.clone(),
                wake: sender,
            },
            Publications { state, wake },
        )
    }
    fn update(&self, change: impl FnOnce(&mut State) -> bool) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("Touch Bar state unavailable"))?;
        let mut next = state.clone();
        if !change(&mut next) {
            return Ok(());
        }
        if next.snapshot == state.snapshot {
            *state = next;
            return Ok(());
        }
        next.snapshot.generation = state
            .snapshot
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Touch Bar generation exhausted"))?;
        next.json()?;
        *state = next;
        // Coalesce only wakeups. The latest complete immutable projection is
        // read serially by the publisher; a slow observer never stalls the UI.
        let _ = self.wake.try_send(());
        Ok(())
    }
    pub fn begin(
        &self,
        key: RequestKey,
        presentation: &Presentation,
        choosing: bool,
        deadline: Deadline,
    ) -> io::Result<()> {
        presentation.validate()?;
        if presentation.id != key.id {
            return Err(io::Error::other("Touch Bar request mismatch"));
        }
        let target = match &presentation.target {
            Some(PromptTarget::WebAuthn { rp_id, .. }) => Some(Target::WebAuthn {
                rp_id: rp_id.clone(),
            }),
            Some(PromptTarget::Login { website }) => Some(Target::Login {
                website: website.clone(),
            }),
            None => None,
        };
        self.update(|state| {
            if state.key.is_some() {
                return false;
            }
            state.key = Some(key);
            state.snapshot.request = Some(Request {
                id: key.id,
                operation: presentation.operation,
                target,
                storage: presentation.storage,
                phase: if choosing {
                    PromptPhase::ChoosingStorage
                } else if presentation.operation == PromptOperation::DiagnosticCancel {
                    PromptPhase::DiagnosticCancel
                } else {
                    PromptPhase::Presenting
                },
                desktop_visible: false,
                cancelable: true,
                expires_at_monotonic_usec: deadline.0,
                message: String::new(),
            });
            true
        })
    }
    pub fn bind(
        &self,
        key: RequestKey,
        presentation: &Presentation,
        deadline: Deadline,
    ) -> io::Result<()> {
        presentation.validate()?;
        self.update(|state| {
            if state.key != Some(key) || presentation.id != key.id {
                return false;
            }
            let Some(request) = state.snapshot.request.as_mut().or(state.hidden.as_mut()) else {
                return false;
            };
            request.storage = presentation.storage;
            request.desktop_visible = false;
            request.phase = PromptPhase::Presenting;
            request.expires_at_monotonic_usec = deadline.0;
            request.message.clear();
            true
        })
    }
    pub fn hide(&self, key: RequestKey) -> io::Result<()> {
        self.update(|state| {
            if state.key != Some(key) || state.snapshot.request.is_none() {
                return false;
            }
            state.hidden = state.snapshot.request.take();
            true
        })
    }
    pub fn visible(&self, key: RequestKey) -> io::Result<()> {
        self.update(|state| {
            if state.key != Some(key) {
                return false;
            }
            if state.snapshot.request.is_none() {
                state.snapshot.request = state.hidden.take();
            }
            let Some(request) = state.snapshot.request.as_mut().or(state.hidden.as_mut()) else {
                return false;
            };
            request.desktop_visible = true;
            // An asynchronous Visible callback cannot regress newer typed guidance.
            if request.phase == PromptPhase::Presenting {
                request.phase = PromptPhase::Preparing;
            }
            true
        })
    }
    pub fn status(
        &self,
        key: RequestKey,
        phase: PromptPhase,
        deadline: Deadline,
        message: &str,
    ) -> io::Result<()> {
        super::validate_status(message)?;
        self.update(|state| {
            if state.key != Some(key) {
                return false;
            }
            let Some(request) = state.snapshot.request.as_mut().or(state.hidden.as_mut()) else {
                return false;
            };
            request.phase = if request.operation == PromptOperation::DiagnosticCancel {
                PromptPhase::DiagnosticCancel
            } else {
                phase
            };
            request.message = message.into();
            request.expires_at_monotonic_usec = deadline.0;
            true
        })
    }
    pub fn retire(&self, key: RequestKey) -> io::Result<()> {
        self.update(|state| {
            if state.key != Some(key) {
                return false;
            }
            state.key = None;
            state.hidden = None;
            state.snapshot.request = None;
            true
        })
    }
    pub fn interface(&self, commands: mpsc::SyncSender<CancelCommand>) -> TouchBar {
        TouchBar {
            state: self.state.clone(),
            commands,
        }
    }
}
impl Publications {
    /// Exactly one serial emitter. It holds no UI entities, ignores delivery
    /// failures, and imposes a timeout on its own bus work, never on the desktop.
    pub fn run(self, bus: zbus::Connection) {
        std::thread::spawn(move || {
            let mut sent = 0;
            while self.wake.recv().is_ok() {
                let next = self.state.lock().ok().and_then(|state| {
                    state
                        .json()
                        .ok()
                        .map(|json| (state.snapshot.generation, json))
                });
                let Some((generation, json)) = next else {
                    continue;
                };
                if generation <= sent {
                    continue;
                }
                let changed = std::collections::HashMap::from([(
                    "Snapshot",
                    zbus::zvariant::Value::from(json.as_str()),
                )]);
                let body = (INTERFACE, changed, Vec::<&str>::new());
                async_io::block_on(futures_lite::future::or(
                    async {
                        let _ = bus
                            .emit_signal(
                                None::<&str>,
                                PATH,
                                "org.freedesktop.DBus.Properties",
                                "PropertiesChanged",
                                &body,
                            )
                            .await;
                    },
                    async {
                        async_io::Timer::after(Duration::from_secs(1)).await;
                    },
                ));
                sent = generation;
            }
        });
    }
}
pub struct TouchBar {
    state: Arc<Mutex<State>>,
    commands: mpsc::SyncSender<CancelCommand>,
}
#[zbus::interface(name = "cameroncooper.keychain.AuthenticationAgent.TouchBar1")]
impl TouchBar {
    #[zbus(property)]
    fn snapshot(&self) -> zbus::fdo::Result<String> {
        self.state
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("Presentation state unavailable".into()))?
            .json()
            .map_err(|_| zbus::fdo::Error::Failed("Presentation state unavailable".into()))
    }
    async fn cancel(&self, request_id: &str) -> zbus::fdo::Result<()> {
        let id = Uuid::parse_str(request_id)
            .ok()
            .filter(|id| !id.is_nil() && request_id.len() == 36 && id.to_string() == request_id)
            .ok_or_else(|| {
                zbus::fdo::Error::InvalidArgs("Expected a canonical non-nil request UUID".into())
            })?;
        let key = {
            let state = self
                .state
                .lock()
                .map_err(|_| zbus::fdo::Error::Failed("Presentation state unavailable".into()))?;
            state
                .key
                .filter(|key| key.id == id && state.snapshot.request.is_some())
        };
        let Some(key) = key else {
            return Ok(());
        };
        let (applied, reply) = mpsc::sync_channel(1);
        self.commands
            .try_send(CancelCommand { key, applied })
            .map_err(|_| {
                zbus::fdo::Error::Failed("Presentation command queue unavailable".into())
            })?;
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match reply.try_recv() {
                Ok(()) => return Ok(()),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(zbus::fdo::Error::Failed(
                        "Presentation command canceled".into(),
                    ));
                }
                Err(mpsc::TryRecvError::Empty) => (),
            }
            if Instant::now() >= deadline {
                return Err(zbus::fdo::Error::Failed(
                    "Presentation command timed out".into(),
                ));
            }
            async_io::Timer::after(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> RequestKey {
        RequestKey {
            id: Uuid::new_v4(),
            connection: Uuid::new_v4(),
        }
    }
    fn presentation(key: RequestKey) -> Presentation {
        Presentation::passkey(
            key.id,
            PromptOperation::UsePasskey,
            "example.com",
            Some("https://login.example.com"),
            "do-not-export-account",
            crate::model::PasskeyProvenance::Synced,
        )
    }
    fn snapshot(publication: &Publication) -> serde_json::Value {
        let state = publication.state.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::from_str(&state.json().unwrap_or_else(|e| panic!("snapshot: {e}")))
            .unwrap_or_else(|e| panic!("json: {e}"))
    }
    #[test]
    fn absent_or_slow_consumer_coalesces_without_blocking_state() -> io::Result<()> {
        let (publication, updates) = Publication::new();
        let key = key();
        publication.begin(key, &presentation(key), false, Deadline(None))?;
        for tick in 0..1000 {
            publication.status(
                key,
                PromptPhase::Preparing,
                Deadline(Some(tick)),
                "Preparing",
            )?;
        }
        assert_eq!(snapshot(&publication)["generation"], 1001);
        assert_eq!(
            snapshot(&publication)["request"]["expires_at_monotonic_usec"],
            999
        );
        assert!(updates.wake.try_recv().is_ok());
        assert!(updates.wake.try_recv().is_err());
        drop(updates);
        publication.retire(key)?;
        assert!(snapshot(&publication)["request"].is_null());
        Ok(())
    }
    #[test]
    fn exhausted_generation_leaves_existing_snapshot_unchanged() -> io::Result<()> {
        let (publication, _) = Publication::new();
        let key = key();
        publication.begin(key, &presentation(key), false, Deadline(None))?;
        publication
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot
            .generation = u64::MAX;
        let before = snapshot(&publication);
        assert!(publication.retire(key).is_err());
        assert_eq!(snapshot(&publication), before);
        Ok(())
    }
    #[test]
    fn projection_is_atomic_bounded_and_contains_no_private_context() -> io::Result<()> {
        let (publication, _) = Publication::new();
        let key = key();
        assert_eq!(
            snapshot(&publication),
            serde_json::json!({"version":1,"generation":0,"request":null})
        );
        publication.begin(key, &presentation(key), false, Deadline(None))?;
        let value = snapshot(&publication);
        assert_eq!(value["request"]["id"], key.id.to_string());
        assert_eq!(
            value["request"]["target"],
            serde_json::json!({"kind":"web-authn","rp_id":"example.com"})
        );
        assert_eq!(value["request"]["storage"], "i-cloud-synced");
        assert_eq!(value["request"]["desktop_visible"], false);
        assert_eq!(
            value["request"]["expires_at_monotonic_usec"],
            serde_json::Value::Null
        );
        let serialized = value.to_string();
        for forbidden in [
            "do-not-export-account",
            "https://login.example.com",
            "account",
            "connection",
            "credential",
        ] {
            assert!(!serialized.contains(forbidden));
        }
        publication.status(
            key,
            PromptPhase::PlaceFinger,
            Deadline(Some(123)),
            "Touch the fingerprint reader",
        )?;
        publication.visible(key)?;
        let value = snapshot(&publication);
        assert_eq!(value["request"]["phase"], "place-finger");
        assert_eq!(value["request"]["desktop_visible"], true);
        let generation = value["generation"].clone();
        publication.visible(key)?;
        publication.status(
            key,
            PromptPhase::PlaceFinger,
            Deadline(Some(123)),
            "Touch the fingerprint reader",
        )?;
        assert_eq!(snapshot(&publication)["generation"], generation);
        assert!(
            publication
                .status(
                    key,
                    PromptPhase::Processing,
                    Deadline(None),
                    &"a".repeat(513)
                )
                .is_err()
        );
        assert!(
            publication
                .status(
                    key,
                    PromptPhase::Processing,
                    Deadline(None),
                    "bad\u{202e}text"
                )
                .is_err()
        );
        publication.retire(key)?;
        assert_eq!(snapshot(&publication)["request"], serde_json::Value::Null);
        let generation = snapshot(&publication)["generation"].clone();
        publication.retire(key)?;
        assert_eq!(snapshot(&publication)["generation"], generation);
        Ok(())
    }
    #[test]
    fn stale_connection_events_never_clear_or_replace_the_current_request() -> io::Result<()> {
        let (publication, _) = Publication::new();
        let first = key();
        let rejected = RequestKey {
            connection: Uuid::new_v4(),
            ..first
        };
        publication.begin(first, &presentation(first), false, Deadline(None))?;
        publication.visible(first)?;
        publication.begin(rejected, &presentation(rejected), false, Deadline(None))?;
        let before = snapshot(&publication);
        publication.status(
            rejected,
            PromptPhase::Processing,
            Deadline(Some(0)),
            "obsolete",
        )?;
        publication.bind(rejected, &presentation(rejected), Deadline(None))?;
        publication.retire(rejected)?;
        assert_eq!(snapshot(&publication), before);
        publication.retire(first)?;
        publication.begin(rejected, &presentation(rejected), false, Deadline(None))?;
        publication.retire(first)?;
        assert_eq!(
            snapshot(&publication)["request"]["id"],
            rejected.id.to_string()
        );
        Ok(())
    }
    #[test]
    fn chooser_rebind_and_focus_restore_preserve_stage_timing_and_typed_status() -> io::Result<()> {
        let (publication, _) = Publication::new();
        let key = key();
        let mut request = presentation(key);
        request.operation = PromptOperation::CreatePasskey;
        publication.begin(key, &request, true, Deadline(None))?;
        publication.visible(key)?;
        publication.status(
            key,
            PromptPhase::ChoosingStorage,
            Deadline(Some(100)),
            "Choose storage",
        )?;
        publication.hide(key)?;
        assert!(snapshot(&publication)["request"].is_null());
        let generation = snapshot(&publication)["generation"].clone();
        publication.status(
            key,
            PromptPhase::ChoosingStorage,
            Deadline(Some(100)),
            "Choose storage",
        )?;
        assert_eq!(snapshot(&publication)["generation"], generation);
        publication.visible(key)?;
        assert_eq!(
            snapshot(&publication)["request"]["expires_at_monotonic_usec"],
            100
        );
        request.storage = Some(PromptStorage::DeviceOnly);
        publication.bind(key, &request, Deadline(None))?;
        assert_eq!(snapshot(&publication)["request"]["desktop_visible"], false);
        assert!(snapshot(&publication)["request"]["expires_at_monotonic_usec"].is_null());
        publication.visible(key)?;
        publication.status(key, PromptPhase::Preparing, Deadline(Some(200)), "Prepare")?;
        publication.status(key, PromptPhase::Preparing, Deadline(Some(200)), "Prepare")?;
        assert_eq!(
            snapshot(&publication)["request"]["expires_at_monotonic_usec"],
            200
        );
        publication.status(key, PromptPhase::Processing, Deadline(Some(200)), "Saving")?;
        publication.visible(key)?;
        assert_eq!(snapshot(&publication)["request"]["phase"], "processing");
        Ok(())
    }
    #[test]
    fn diagnostic_cancellation_never_invites_a_finger() -> io::Result<()> {
        let (publication, _) = Publication::new();
        let key = key();
        publication.begin(
            key,
            &Presentation::diagnostic(key.id, PromptOperation::DiagnosticCancel, "ignored account"),
            false,
            Deadline(None),
        )?;
        publication.visible(key)?;
        publication.status(
            key,
            PromptPhase::PlaceFinger,
            Deadline(Some(0)),
            "Do not touch",
        )?;
        assert_eq!(
            snapshot(&publication)["request"]["phase"],
            "diagnostic-cancel"
        );
        assert_eq!(
            snapshot(&publication)["request"]["expires_at_monotonic_usec"],
            0
        );
        Ok(())
    }
    #[test]
    fn cancel_validation_staleness_full_queue_and_shutdown_are_bounded() -> io::Result<()> {
        let (publication, _) = Publication::new();
        let key = key();
        let (tx, rx) = mpsc::sync_channel(1);
        let interface = publication.interface(tx);
        async_io::block_on(async {
            for invalid in [
                "",
                "not-a-uuid",
                "00000000-0000-0000-0000-000000000000",
                "ABCDEFAB-ABCD-4ABC-8ABC-ABCDEFABCDEF",
            ] {
                assert!(matches!(
                    interface.cancel(invalid).await,
                    Err(zbus::fdo::Error::InvalidArgs(_))
                ));
            }
            interface
                .cancel(&key.id.to_string())
                .await
                .unwrap_or_else(|e| panic!("stale: {e}"));
        });
        publication.begin(key, &presentation(key), false, Deadline(None))?;
        let cloned = publication.clone();
        let ui = std::thread::spawn(move || {
            let command = rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap_or_else(|e| panic!("command: {e}"));
            assert_eq!(command.key, key);
            cloned.retire(key).unwrap_or_else(|e| panic!("retire: {e}"));
            command.applied();
        });
        async_io::block_on(interface.cancel(&key.id.to_string()))
            .unwrap_or_else(|e| panic!("cancel: {e}"));
        ui.join()
            .map_err(|_| io::Error::other("UI fixture failed"))?;
        publication.begin(key, &presentation(key), false, Deadline(None))?;
        // UI receiver is gone; this cannot turn into an indefinitely waiting call.
        assert!(async_io::block_on(interface.cancel(&key.id.to_string())).is_err());
        let (tx, rx) = mpsc::sync_channel(1);
        let interface = publication.interface(tx);
        let before = Instant::now();
        assert!(async_io::block_on(interface.cancel(&key.id.to_string())).is_err());
        assert!(before.elapsed() < Duration::from_secs(2));
        // Timed-out queued work retains the exact connection key, even if the
        // root caller later reuses the same public UUID on a new connection.
        let timed_out = rx.try_recv().map_err(io::Error::other)?;
        publication.retire(key)?;
        let replacement = RequestKey {
            connection: Uuid::new_v4(),
            ..key
        };
        publication.begin(
            replacement,
            &presentation(replacement),
            false,
            Deadline(None),
        )?;
        assert_ne!(timed_out.key, replacement);
        publication.retire(timed_out.key)?;
        timed_out.applied();
        assert!(snapshot(&publication)["request"].is_object());
        let (reply, _) = mpsc::sync_channel(1);
        interface
            .commands
            .try_send(CancelCommand {
                key: replacement,
                applied: reply,
            })
            .map_err(io::Error::other)?;
        let before = Instant::now();
        assert!(async_io::block_on(interface.cancel(&replacement.id.to_string())).is_err());
        assert!(before.elapsed() < Duration::from_millis(100));
        Ok(())
    }
}

#[cfg(test)]
#[path = "touchbar_tests.rs"]
mod bus_tests;
