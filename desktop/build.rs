use cxx_qt_build::{CxxQtBuilder, QmlFile, QmlModule};
// One QML module: the Rust bridge plus Folio-shaped components, compiled
// ahead of time by qmlcachegen and embedded as Qt resources.
const COMPONENTS: &[&str] = &[
    "qml/Main.qml",
    "qml/Words.qml",
    "qml/Glyph.qml",
    "qml/PlainButton.qml",
    "qml/IconButton.qml",
    "qml/PlainField.qml",
    "qml/QuietScrollBar.qml",
    "qml/TopBar.qml",
    "qml/Sidebar.qml",
    "qml/AccountList.qml",
    "qml/DetailPane.qml",
    "qml/HelpOverlay.qml",
    "qml/KeychainMenu.qml",
    "qml/MenuEntry.qml",
    "qml/MenuLine.qml",
    "qml/Banner.qml",
    "qml/UnlockView.qml",
];
fn main() {
    let files = COMPONENTS
        .iter()
        .map(QmlFile::from)
        .chain([QmlFile::from("qml/Theme.qml").singleton(true)]);
    CxxQtBuilder::new_qml_module(QmlModule::new("KeychainBackend").qml_files(files))
        .files(["src/backend.rs"])
        .build();
}
