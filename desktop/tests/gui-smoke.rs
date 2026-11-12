//! A separate executable seeds an isolated encrypted vault before Qt starts.
//! The production binary contains no fixture, demo or automation switches.
#[path = "../src/backend.rs"]
mod backend;
#[path = "../src/theme.rs"]
mod theme;
use cxx_qt_lib::{QByteArray, QGuiApplication, QQmlApplicationEngine, QUrl};
use keychain::{
    model::{Credential, VaultState},
    paths::AppPaths,
    security::SoftwareFileBackend,
    store::StateStore,
};
use std::{
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
};

// This fixture needs an exclusive, private directory containing synthetic data.
// UUID is already used by the core, so no extra filesystem feature set is added
// to the Qt test dependency graph.
struct TestProfile(PathBuf);
impl TestProfile {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("keychain-gui-test-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TestProfile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn main() {
    if std::env::args().any(|a| a == "--child") {
        child();
        return;
    }
    for mode in ["dark", "light", "narrow"] {
        let dir = TestProfile::new();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.path().join("runtime"))
            .unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--child")
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .env("XDG_RUNTIME_DIR", dir.path().join("runtime"))
            .env("QT_QPA_PLATFORM", "offscreen")
            .env("QT_QUICK_BACKEND", "software")
            .env("QT_FORCE_STDERR_LOGGING", "1")
            .env("QT_QUICK_CONTROLS_STYLE", "Material")
            .env("KEYCHAIN_TEST_MODE", mode)
            .output()
            .unwrap();
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success() && log.contains("GUI SMOKE PASS"),
            "{mode}: {log}"
        );
        assert!(
            !log.contains("ReferenceError")
                && !log.contains("TypeError")
                && !log.contains("Binding loop"),
            "{mode}: {log}"
        );
        println!("{mode}: {log}");
    }
}
fn child() {
    let mode = std::env::var("KEYCHAIN_TEST_MODE").unwrap();
    let paths = AppPaths::discover().unwrap();
    let backend = SoftwareFileBackend::new(paths.clone());
    let store = StateStore::new(&paths, &backend);
    let mut first = Credential {
        protected: false,
        id: "11111111-1111-4111-8111-111111111111".into(),
        domain: "example.com".into(),
        username: "alice@example.com".into(),
        password: "synthetic-password".into(),
        notes: "synthetic-notes".into(),
        title: "Example".into(),
        modified_at: 1.,
        last_used: 0.,
        totp_uri: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP".into(),
    };
    let mut second = first.clone();
    second.id = "22222222-2222-4222-8222-222222222222".into();
    second.title = "Other".into();
    second.domain = "other.example".into();
    second.totp_uri.clear();
    store
        .save_vault(&VaultState {
            schema_version: 1,
            synced_at: 1,
            credentials: vec![first.clone(), second],
            passkeys: vec![],
        })
        .unwrap();
    first.password.clear();
    let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
    let colors = home.join(".local/state/omarchy/current/theme");
    std::fs::create_dir_all(&colors).unwrap();
    let palette = if mode == "light" {
        "background = '#f4f3ef'\ndark_background = '#eae9e4'\nforeground = '#29292e'\nbright_foreground = '#202025'\naccent = '#806400'\n"
    } else {
        "background = '#16161a'\ndark_background = '#111114'\nforeground = '#c8c8d0'\nbright_foreground = '#ececf1'\naccent = '#ffd60a'\n"
    };
    std::fs::write(colors.join("colors.toml"), palette).unwrap();
    let mut app = QGuiApplication::new();
    let mut engine = QQmlApplicationEngine::new();
    let _failure = engine
        .pin_mut()
        .on_object_creation_failed(|_, _| std::process::exit(1));
    let source = include_str!("../qml/Main.qml");
    let mut source = source[..source.rfind('}').unwrap()].to_string();
    source.push_str(&format!("\nproperty string testMode: \"{mode}\"\n"));
    source.push_str(include_str!("smoke.qml"));
    source.push('}');
    engine.pin_mut().load_data(
        &QByteArray::from(source.as_bytes()),
        &QUrl::from("qrc:/KeychainTest.qml"),
    );
    let code = app.pin_mut().exec();
    drop(engine);
    drop(app);
    std::process::exit(code);
}
