use cxx_qt_build::{CxxQtBuilder, QmlModule};
fn main() {
    CxxQtBuilder::new_qml_module(QmlModule::new("KeychainBackend"))
        .files(["src/backend.rs"])
        .build();
}
