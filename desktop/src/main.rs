mod backend;
mod theme;
use cxx_qt_lib::{QByteArray, QGuiApplication, QQmlApplicationEngine, QUrl};
fn main() {
    if let Err(error) = keychain_sep_driver::memory::make_process_nondumpable() {
        eprintln!("keychain-gui: {error}");
        std::process::exit(1);
    }
    if keychain_sep_driver::peer::effective_uid() == 0 {
        eprintln!("keychain-gui must run as your desktop user");
        std::process::exit(1);
    }
    let mut app = QGuiApplication::new();
    QGuiApplication::set_desktop_file_name(&"cameroncooper.keychain".into());
    let mut engine = QQmlApplicationEngine::new();
    let _load_failure = engine.pin_mut().on_object_creation_failed(|_, _| {
        eprintln!("Keychain QML failed to load");
        std::process::exit(1);
    });
    engine.pin_mut().load_data(
        &QByteArray::from(include_str!("../qml/Main.qml").as_bytes()),
        &QUrl::from("qrc:/Keychain.qml"),
    );
    let code = app.pin_mut().exec();
    drop(engine);
    drop(app);
    std::process::exit(code);
}
