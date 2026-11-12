//! Toolkit-independent GUI lifecycle. Workers never own a window or publish secrets.
use super::{Category, Item, display_domain, display_text, load_items, now, reveal_field};
use crate::Result;
use crate::broker::login::{RevealField, RevealedLogin};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender},
};
use std::time::{Duration, Instant};

const REVEAL_LIFETIME: Duration = Duration::from_secs(30);
const FOCUS_GRACE: Duration = Duration::from_secs(2);
enum Completion {
    Inventory(Result<Vec<Item>>),
    Reveal(u64, Box<Item>, RevealField, Result<RevealedLogin>),
}

pub struct Controller {
    items: Vec<Item>,
    selected: Option<String>,
    category: Category,
    query: String,
    generation: u64,
    rows_revision: u64,
    reveal_revision: u64,
    canceled: Arc<AtomicBool>,
    inventory_running: Arc<AtomicBool>,
    reveal_running: Arc<AtomicBool>,
    tx: SyncSender<Completion>,
    rx: Receiver<Completion>,
    pending: bool,
    active: bool,
    shown: Option<(RevealField, RevealedLogin, Instant)>,
    awaiting: Option<(RevealField, RevealedLogin, Instant)>,
    message: String,
}
impl Default for Controller {
    fn default() -> Self {
        let (tx, rx) = mpsc::sync_channel(4);
        Self {
            items: Vec::new(),
            selected: None,
            category: Category::All,
            query: String::new(),
            generation: 0,
            rows_revision: 1,
            reveal_revision: 1,
            canceled: Arc::new(AtomicBool::new(false)),
            inventory_running: Arc::new(AtomicBool::new(false)),
            reveal_running: Arc::new(AtomicBool::new(false)),
            tx,
            rx,
            pending: false,
            active: false,
            shown: None,
            awaiting: None,
            message: String::new(),
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.canceled.store(true, Ordering::Release);
    }
}
impl Controller {
    fn selected(&self) -> Option<&Item> {
        self.items
            .iter()
            .find(|i| self.selected.as_deref() == Some(&i.id))
    }
    fn invalidate(&mut self) {
        self.canceled.store(true, Ordering::Release);
        self.canceled = Arc::new(AtomicBool::new(false));
        self.generation = self.generation.wrapping_add(1);
        self.pending = false;
        self.shown = None;
        self.reveal_revision = self.reveal_revision.wrapping_add(1);
        self.awaiting = None;
    }
    fn reconcile_selection(&mut self) {
        if !self.items.iter().any(|i| {
            self.selected.as_deref() == Some(&i.id) && i.matches(self.category, &self.query)
        }) {
            self.selected = self
                .items
                .iter()
                .find(|i| i.matches(self.category, &self.query))
                .map(|i| i.id.clone());
        }
    }
    pub fn command(&mut self, action: &str, arg: &str) {
        match action {
            "refresh" => self.refresh(),
            "search" | "filter" | "select" => {
                self.invalidate();
                if action != "select" {
                    self.rows_revision = self.rows_revision.wrapping_add(1);
                }
                match action {
                    "search" => {
                        self.query = arg.chars().take(1024).collect::<String>().to_lowercase()
                    }
                    "filter" => {
                        self.category = match arg {
                            "Login" => Category::Passwords,
                            "Passkey" => Category::Passkeys,
                            "Code" => Category::Codes,
                            _ => Category::All,
                        }
                    }
                    _ => {
                        self.selected = self
                            .items
                            .iter()
                            .find(|i| i.id == arg && i.matches(self.category, &self.query))
                            .map(|i| i.id.clone())
                    }
                }
                self.message.clear();
                if action != "select" {
                    self.reconcile_selection();
                }
            }
            "reveal" => match arg {
                "password" => self.start_reveal(RevealField::Password),
                "totp" => self.start_reveal(RevealField::Totp),
                "notes" => self.start_reveal(RevealField::Notes),
                _ => self.message = "Choose one supported field to reveal.".into(),
            },
            "cancel" => {
                self.invalidate();
                self.message.clear();
            }
            "focus" => {
                self.active = arg == "true";
                // The native fingerprint window takes focus. Retain a pending request,
                // but immediately remove anything already displayed.
                if !self.active && self.shown.take().is_some() {
                    self.reveal_revision = self.reveal_revision.wrapping_add(1);
                }
            }
            "tick" => self.tick(Instant::now(), now()),
            _ => {}
        }
    }
    fn refresh(&mut self) {
        if self.inventory_running.swap(true, Ordering::AcqRel) {
            return;
        }
        self.invalidate();
        self.message = "Loading saved accounts…".into();
        let tx = self.tx.clone();
        let running = self.inventory_running.clone();
        std::thread::spawn(move || {
            let result = load_items();
            let _ = tx.send(Completion::Inventory(result));
            running.store(false, Ordering::Release);
        });
    }
    fn start_reveal(&mut self, field: RevealField) {
        let Some(item) = self.selected().cloned() else {
            return;
        };
        let Some(login) = &item.login else {
            return;
        };
        let available = match field {
            RevealField::Password => login.has_password,
            RevealField::Notes => login.has_notes,
            RevealField::Totp => login.has_totp,
            RevealField::All => false,
        };
        if !available || !self.active || self.inventory_running.load(Ordering::Acquire) {
            return;
        }
        if self.reveal_running.swap(true, Ordering::AcqRel) {
            self.message = "Wait for the previous verification to finish.".into();
            return;
        }
        self.invalidate();
        self.pending = true;
        self.message = "Waiting for verification…".into();
        let tx = self.tx.clone();
        let generation = self.generation;
        let canceled = self.canceled.clone();
        let running = self.reveal_running.clone();
        std::thread::spawn(move || {
            let result = reveal_field(&item, field, canceled);
            // A canceled/closed receiver drops the zeroizing response here.
            let _ = tx.send(Completion::Reveal(
                generation,
                Box::new(item),
                field,
                result,
            ));
            running.store(false, Ordering::Release);
        });
    }
    fn accept(&mut self, completion: Completion, at: Instant) {
        match completion {
            Completion::Inventory(result) => match result {
                Ok(items) => {
                    self.invalidate();
                    self.items = items;
                    self.rows_revision = self.rows_revision.wrapping_add(1);
                    self.reconcile_selection();
                    self.message.clear();
                }
                Err(error) => self.message = display_text(&error.to_string()),
            },
            Completion::Reveal(generation, item, field, result)
                if generation == self.generation
                    && !self.canceled.load(Ordering::Acquire)
                    && self.selected() == Some(item.as_ref()) =>
            {
                match result {
                    Ok(value) if valid_response(&item, field, &value) => {
                        self.awaiting = Some((field, value, at))
                    }
                    Ok(_) => {
                        self.pending = false;
                        self.message =
                            "The reveal response did not match the selected field.".into();
                    }
                    Err(error) => {
                        self.pending = false;
                        self.message = display_text(&error.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    fn tick(&mut self, at: Instant, unix: u64) {
        while let Ok(completion) = self.rx.try_recv() {
            self.accept(completion, at);
        }
        if self
            .awaiting
            .as_ref()
            .is_some_and(|(_, _, arrived)| at.duration_since(*arrived) >= FOCUS_GRACE)
        {
            self.awaiting = None;
            self.pending = false;
            self.message = "Return to Keychain and choose Reveal again.".into();
        } else if self.active {
            if let Some((field, value, _)) = self.awaiting.take() {
                self.shown = Some((field, value, at));
                self.reveal_revision = self.reveal_revision.wrapping_add(1);
                self.pending = false;
                self.message.clear();
            }
        }
        if self.shown.as_ref().is_some_and(|(_, value, revealed)| {
            at.duration_since(*revealed) >= REVEAL_LIFETIME
                || value.totp.as_ref().is_some_and(|c| c.expires <= unix)
        }) {
            self.shown = None;
            self.reveal_revision = self.reveal_revision.wrapping_add(1);
        }
    }
    pub fn reveal_revision(&self) -> u64 {
        self.reveal_revision
    }
    /// This borrowed view never enters the inventory JSON or an ordinary String.
    pub fn revealed(&self) -> &str {
        match &self.shown {
            Some((RevealField::Password, v, _)) => {
                v.password.as_deref().map(String::as_str).unwrap_or("")
            }
            Some((RevealField::Notes, v, _)) => {
                v.notes.as_deref().map(String::as_str).unwrap_or("")
            }
            Some((RevealField::Totp, v, _)) => {
                v.totp.as_ref().map(|c| c.code.as_str()).unwrap_or("")
            }
            _ => "",
        }
    }
    pub fn rows_revision(&self) -> u64 {
        self.rows_revision
    }
    pub fn rows(&self) -> Value {
        Value::Array(
            self.items
                .iter()
                .filter(|i| i.matches(self.category, &self.query))
                .map(metadata)
                .collect(),
        )
    }
    pub fn snapshot(&self) -> Value {
        json!({"selected": self.selected().map(metadata), "category": match self.category { Category::All => "All", Category::Passwords => "Login", Category::Passkeys => "Passkey", Category::Codes => "Code" },
            "busy":self.pending, "loading":self.inventory_running.load(Ordering::Acquire), "message":self.message,
            "revealedField":self.shown.as_ref().map(|(f,_,_)| match f { RevealField::Password => "password", RevealField::Notes => "notes", RevealField::Totp => "totp", _ => "" }),
            "expires":self.shown.as_ref().and_then(|(_,v,_)| v.totp.as_ref().map(|c| c.expires))})
    }
}
fn metadata(item: &Item) -> Value {
    json!({"id":item.id, "site":display_text(&item.title), "domain":display_domain(&item.domain), "account":display_text(&item.username),
        "kind":if item.login.is_some() {"Login"}else{"Passkey"}, "storage":item.storage, "protection":item.protection,
        "password":item.login.as_ref().is_some_and(|l| l.has_password), "notes":item.login.as_ref().is_some_and(|l| l.has_notes), "totp":item.login.as_ref().is_some_and(|l| l.has_totp)})
}
fn valid_response(item: &Item, field: RevealField, value: &RevealedLogin) -> bool {
    value.id == item.id
        && item
            .route
            .as_ref()
            .map_or(value.revision == 0, |r| r.revision == value.revision)
        && match field {
            RevealField::Password => {
                value.password.is_some() && value.notes.is_none() && value.totp.is_none()
            }
            RevealField::Notes => {
                value.password.is_none() && value.notes.is_some() && value.totp.is_none()
            }
            RevealField::Totp => {
                value.password.is_none() && value.notes.is_none() && value.totp.is_some()
            }
            RevealField::All => false,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::login::LoginMetadata;
    fn item() -> Item {
        Item {
            id: "a".into(),
            title: "Example".into(),
            domain: "example.com".into(),
            username: "alice".into(),
            storage: "iCloud-synced",
            protection: "Software-encrypted cache",
            route: None,
            login: Some(LoginMetadata {
                id: "a".into(),
                title: "Example".into(),
                domain: "example.com".into(),
                username: "alice".into(),
                modified_at: 1.,
                last_used: 0.,
                has_password: true,
                has_notes: true,
                has_totp: true,
            }),
        }
    }
    fn controller() -> Controller {
        let mut c = Controller::default();
        c.items.push(item());
        c.active = true;
        c.reconcile_selection();
        c
    }
    fn response() -> RevealedLogin {
        RevealedLogin {
            id: "a".into(),
            revision: 0,
            password: Some("synthetic-secret".to_owned().into()),
            notes: None,
            totp: None,
        }
    }
    fn deliver(c: &mut Controller, at: Instant) {
        c.accept(
            Completion::Reveal(
                c.generation,
                Box::new(item()),
                RevealField::Password,
                Ok(response()),
            ),
            at,
        );
        c.tick(at, 0);
    }
    #[test]
    fn stale_canceled_and_changed_metadata_results_are_discarded() {
        for action in ["select", "search", "filter", "cancel"] {
            let mut c = controller();
            let generation = c.generation;
            c.command(action, "");
            c.accept(
                Completion::Reveal(
                    generation,
                    Box::new(item()),
                    RevealField::Password,
                    Ok(response()),
                ),
                Instant::now(),
            );
            c.tick(Instant::now(), 0);
            assert!(c.revealed().is_empty());
        }
        let mut c = controller();
        c.items[0].username = "changed".into();
        deliver(&mut c, Instant::now());
        assert!(c.revealed().is_empty());
    }
    #[test]
    fn fingerprint_focus_handoff_does_not_cancel_but_late_return_discards() {
        let at = Instant::now();
        let mut c = controller();
        c.pending = true;
        c.command("focus", "false");
        assert!(!c.canceled.load(Ordering::Acquire));
        deliver(&mut c, at);
        assert!(c.revealed().is_empty());
        c.command("focus", "true");
        c.tick(at + Duration::from_millis(100), 0);
        assert_eq!(c.revealed(), "synthetic-secret");
        c.command("focus", "false");
        assert!(c.revealed().is_empty());
        deliver(&mut c, at);
        c.command("focus", "true");
        c.tick(at + FOCUS_GRACE, 0);
        assert!(c.revealed().is_empty());
        assert!(!c.pending);
    }
    #[test]
    fn timeout_code_expiry_and_metadata_snapshot_keep_fields_private() {
        let at = Instant::now();
        let mut c = controller();
        deliver(&mut c, at);
        assert_eq!(c.revealed(), "synthetic-secret");
        assert!(!c.snapshot().to_string().contains("synthetic-secret"));
        assert!(!c.rows().to_string().contains("synthetic-secret"));
        c.tick(at + REVEAL_LIFETIME, 0);
        assert!(c.revealed().is_empty());
        let mut value = response();
        value.password = None;
        value.totp = Some(crate::totp::GeneratedCode {
            code: "123456".into(),
            expires: 100,
            period: 30,
        });
        c.accept(
            Completion::Reveal(c.generation, Box::new(item()), RevealField::Totp, Ok(value)),
            at,
        );
        c.tick(at, 99);
        assert_eq!(c.revealed(), "123456");
        c.tick(at + Duration::from_millis(100), 100);
        assert!(c.revealed().is_empty());
    }
    #[test]
    fn extra_fields_wrong_revision_or_identity_fail_closed() {
        let at = Instant::now();
        for case in 0..4 {
            let mut c = controller();
            let mut value = response();
            match case {
                0 => value.notes = Some("unrequested".to_owned().into()),
                1 => value.id = "b".into(),
                2 => value.revision = 1,
                _ => value.password = None,
            }
            c.accept(
                Completion::Reveal(
                    c.generation,
                    Box::new(item()),
                    RevealField::Password,
                    Ok(value),
                ),
                at,
            );
            c.tick(at, 0);
            assert!(c.revealed().is_empty());
            assert!(!c.pending);
        }
    }
    #[test]
    fn destruction_cancels_workers_and_refresh_invalidates_revealed_value() {
        let at = Instant::now();
        let mut c = controller();
        let canceled = c.canceled.clone();
        deliver(&mut c, at);
        c.accept(Completion::Inventory(Ok(vec![item()])), at);
        assert!(c.revealed().is_empty());
        assert!(canceled.load(Ordering::Acquire));
        let canceled = c.canceled.clone();
        drop(c);
        assert!(canceled.load(Ordering::Acquire));
    }
}
