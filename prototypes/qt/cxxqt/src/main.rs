mod backend;
use cxx_qt_lib::{QByteArray, QGuiApplication, QQmlApplicationEngine, QUrl};
fn main() {
    let mut app = QGuiApplication::new();
    QGuiApplication::set_desktop_file_name(&"keychain-qt-prototype".into());
    let mut engine = QQmlApplicationEngine::new();
    let _load_failure = engine.pin_mut().on_object_creation_failed(|_, _| {
        eprintln!("Prototype QML failed to load");
        std::process::exit(1);
    });
    let source = include_str!("../../qml/Main.qml");
    engine.pin_mut().load_data(
        &QByteArray::from(source.as_bytes()),
        &QUrl::from("qrc:/Prototype.qml"),
    );
    let code = app.pin_mut().exec();
    drop(engine);
    drop(app);
    std::process::exit(code);
}
