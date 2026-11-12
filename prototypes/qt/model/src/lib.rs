//! Synthetic-only view state. This crate has no Keychain, IPC or device dependency.
use serde::Serialize;
use std::io::Read;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

static LIVE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Serialize)]
pub struct Item {
    pub id: String,
    pub site: String,
    pub account: String,
    pub kind: String,
    pub storage: String,
}
#[derive(Clone)]
pub struct Job {
    generation: u64,
    id: String,
    fail: bool,
}
pub struct Model {
    items: Vec<Item>,
    query: String,
    category: String,
    selected: String,
    generation: u64,
    busy: bool,
    message: String,
    pub revealed: String,
    fail_next: bool,
    workers: Arc<AtomicUsize>,
}
impl Default for Model {
    fn default() -> Self {
        let items = fixtures();
        LIVE.fetch_add(1, Ordering::AcqRel);
        Self {
            selected: items[0].id.clone(),
            items,
            query: String::new(),
            category: "All".into(),
            generation: 0,
            busy: false,
            message: String::new(),
            revealed: String::new(),
            fail_next: false,
            workers: Arc::new(AtomicUsize::new(0)),
        }
    }
}
fn fixtures() -> Vec<Item> {
    [
        ("1", "github.com", "alex@example.com", "Login", "iCloud"),
        ("2", "webauthn.io", "alex-demo", "Passkey", "This device"),
        (
            "3",
            "authentication.example",
            "alex@example.com",
            "Code",
            "iCloud",
        ),
        (
            "4",
            "mail.example",
            "alex@studio.example",
            "Login",
            "iCloud",
        ),
        ("5", "design.example", "Studio", "Passkey", "iCloud"),
        ("6", "notes.example", "alex@example.com", "Login", "iCloud"),
    ]
    .into_iter()
    .map(|(id, site, account, kind, storage)| Item {
        id: id.into(),
        site: site.into(),
        account: account.into(),
        kind: kind.into(),
        storage: storage.into(),
    })
    .collect()
}
impl Drop for Model {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Model {
    fn visible(&self) -> Vec<Item> {
        let query = self.query.to_lowercase();
        self.items
            .iter()
            .filter(|i| {
                (self.category == "All" || i.kind == self.category)
                    && format!("{} {}", i.site, i.account)
                        .to_lowercase()
                        .contains(&query)
            })
            .cloned()
            .collect()
    }
    pub fn snapshot(&self) -> String {
        serde_json::json!({"items":self.visible(), "selected":self.items.iter().find(|i|i.id==self.selected),
            "liveModels":LIVE.load(Ordering::Acquire),"previewWidth":std::env::var("KEYCHAIN_QT_WIDTH").ok().and_then(|v|v.parse::<u32>().ok()).unwrap_or(1200).clamp(540,2000),"category":self.category,"busy":self.busy,"message":self.message,"theme":theme(),
            "smoke":std::env::var_os("KEYCHAIN_QT_SMOKE").is_some(),
            "screenshot":std::env::var("KEYCHAIN_QT_SCREENSHOT").unwrap_or_default()}).to_string()
    }
    pub fn command(&mut self, action: &str, arg: &str) -> Option<Job> {
        if action == "theme" {
            return None;
        }
        if action == "fail-next" {
            self.fail_next = true;
            return None;
        }
        if action == "reveal" {
            if self.busy
                || !self
                    .items
                    .iter()
                    .any(|i| i.id == self.selected && i.kind != "Passkey")
            {
                return None;
            }
            self.generation += 1;
            self.busy = true;
            self.revealed.clear();
            self.message = "Simulating verification…".into();
            return Some(Job {
                generation: self.generation,
                id: self.selected.clone(),
                fail: std::mem::take(&mut self.fail_next),
            });
        }
        self.generation += 1;
        self.busy = false;
        self.revealed.clear();
        self.message.clear();
        match action {
            "select" => {
                if self.visible().iter().any(|i| i.id == arg) {
                    self.selected = arg.into()
                }
            }
            "search" => self.query = arg.chars().take(256).collect(),
            "filter" => {
                if ["All", "Login", "Passkey", "Code"].contains(&arg) {
                    self.category = arg.into()
                }
            }
            "refresh" => self.items = fixtures(),
            "remove" => self.items.retain(|i| i.id != self.selected),
            "add" if !self.items.iter().any(|i| i.id == "extra") => {
                self.items.push(Item {
                    id: "extra".into(),
                    site: "new.example".into(),
                    account: "New account".into(),
                    kind: "Login".into(),
                    storage: "This device".into(),
                });
            }
            _ => (),
        }
        let visible = self.visible();
        if !visible.iter().any(|i| i.id == self.selected) {
            self.selected = visible.first().map(|i| i.id.clone()).unwrap_or_default();
        }
        None
    }
    pub fn complete(&mut self, job: Job) {
        if !self.busy || job.generation != self.generation || job.id != self.selected {
            return;
        }
        self.busy = false;
        if job.fail {
            self.message = "Preview verification failed. Try again.".into();
            return;
        }
        self.revealed = if self
            .items
            .iter()
            .any(|i| i.id == job.id && i.kind == "Code")
        {
            "123 456"
        } else {
            "sample-only-password"
        }
        .into();
        self.message = "Sample value · automatically hidden after 10 seconds".into();
    }
    /// Bound synthetic background work; callback owns only a weak Qt dispatch handle.
    pub fn launch(&mut self, job: Job, callback: impl FnOnce(Job) + Send + 'static) {
        if self
            .workers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 4).then_some(n + 1)
            })
            .is_err()
        {
            self.busy = false;
            self.message = "Preview worker is busy. Try again.".into();
            return;
        }
        let workers = self.workers.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            callback(job);
            workers.fetch_sub(1, Ordering::AcqRel);
        });
    }
}
fn theme() -> serde_json::Value {
    let light = std::env::var("KEYCHAIN_QT_THEME").as_deref() == Ok("light");
    let mut colors = serde_json::json!({"background":if light{"#f4f3ef"}else{"#16161a"},
        "detail":if light{"#eae9e4"}else{"#111114"},"foreground":if light{"#29292e"}else{"#c8c8d0"},
        "bright":if light{"#202025"}else{"#ececf1"},"accent":if light{"#806400"}else{"#ffd60a"},"onAccent":"#16161a","radius":0});
    if std::env::var_os("KEYCHAIN_QT_THEME").is_none()
        && let Some(home) = std::env::var_os("HOME")
    {
        let path =
            std::path::PathBuf::from(home).join(".local/state/omarchy/current/theme/colors.toml");
        if let Ok(input) = std::fs::File::open(path) {
            let mut file = String::new();
            if input.take(65537).read_to_string(&mut file).is_ok() && file.len() <= 65536 {
                for line in file.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        let key = key.trim();
                        let value = value.trim().trim_matches(['\'', '"']);
                        let target = match key {
                            "background" => "background",
                            "dark_background" => "detail",
                            "foreground" => "foreground",
                            "bright_foreground" => "bright",
                            "accent" => "accent",
                            _ => continue,
                        };
                        if value.len() == 7
                            && value.starts_with('#')
                            && value[1..].bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            colors[target] = value.into();
                        }
                    }
                }
            }
        }
    }
    let accent = colors["accent"].as_str().unwrap_or("#ffd60a");
    let background = colors["background"].as_str().unwrap_or("#16161a");
    let a = luminance(accent);
    let b = luminance(background);
    let contrast = (a.max(b) + 0.05) / (a.min(b) + 0.05);
    let selection = if contrast >= 4.5 {
        colors["accent"].clone()
    } else {
        colors["foreground"].clone()
    };
    let foreground = colors["foreground"].as_str().unwrap_or("#c8c8d0");
    colors["secondary"] = mix(background, foreground, 0.68).into();
    colors["selectionInk"] = selection;
    colors["onAccent"] = if a > 0.179 { "#000000" } else { "#ffffff" }.into();
    colors
}
// Folio derives secondary text from the base palette rather than per-widget opacity.
fn mix(background: &str, foreground: &str, amount: f64) -> String {
    let bg = u32::from_str_radix(background.trim_start_matches('#'), 16).unwrap_or(0);
    let fg = u32::from_str_radix(foreground.trim_start_matches('#'), 16).unwrap_or(0);
    let channel = |shift: u32| {
        (((bg >> shift) & 255) as f64 * (1.0 - amount) + ((fg >> shift) & 255) as f64 * amount)
            .round() as u8
    };
    format!("#{:02x}{:02x}{:02x}", channel(16), channel(8), channel(0))
}
fn luminance(hex: &str) -> f64 {
    let rgb = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0);
    let linear = |shift: u32| {
        let v = ((rgb >> shift) & 255u32) as f64 / 255.0;
        if v <= 0.04045 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(16) + 0.7152 * linear(8) + 0.0722 * linear(0)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_cancel_and_late_results_do_not_reveal() {
        for action in ["select", "search", "filter", "remove", "cancel"] {
            let mut m = Model::default();
            let job = m.command("reveal", "").unwrap();
            m.command(action, "2");
            m.complete(job);
            assert!(m.revealed.is_empty());
        }
    }
    #[test]
    fn stale_result_cannot_complete_a_new_request() {
        let mut m = Model::default();
        let old = m.command("reveal", "").unwrap();
        m.command("cancel", "");
        let new = m.command("reveal", "").unwrap();
        m.complete(old);
        assert!(m.busy);
        m.complete(new);
        assert!(!m.revealed.is_empty());
        assert!(!m.snapshot().contains("sample-only-password"));
    }
    #[test]
    fn workers_are_bounded_and_do_not_own_the_model() {
        let mut model = Model::default();
        let job = model.command("reveal", "").unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        for _ in 0..5 {
            let sender = sender.clone();
            model.launch(job.clone(), move |_| {
                let _ = sender.send(());
            });
        }
        assert!(!model.busy);
        drop(model);
        drop(sender);
        for _ in 0..4 {
            receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        assert!(receiver.recv_timeout(Duration::from_secs(1)).is_err());
    }
    #[test]
    fn filtering_removal_reset_and_error() {
        let mut m = Model::default();
        m.command("filter", "Passkey");
        assert_eq!(m.visible().len(), 2);
        assert!(m.command("reveal", "").is_none());
        m.command("filter", "Login");
        m.command("fail-next", "");
        let job = m.command("reveal", "").unwrap();
        m.complete(job);
        assert!(m.revealed.is_empty());
        assert!(!m.message.is_empty());
        m.command("remove", "");
        assert_eq!(m.visible().len(), 2);
        m.command("refresh", "");
        assert_eq!(m.visible().len(), 3);
    }
}
