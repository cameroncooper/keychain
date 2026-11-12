use qtbridge::{QApp, QmlObject, qobject};
pub struct Backend {
    snapshot: String,
    revealed: String,
    model: prototype_model::Model,
}
impl Default for Backend {
    fn default() -> Self {
        let model = prototype_model::Model::default();
        Self {
            snapshot: model.snapshot(),
            revealed: String::new(),
            model,
        }
    }
}
#[qobject]
impl Backend {
    qproperty!("snapshot", Member = snapshot, Notify = snapshot_changed);
    qproperty!("revealed", Member = revealed, Notify = revealed_changed);
    #[qsignal]
    fn snapshot_changed(&mut self);
    #[qsignal]
    fn revealed_changed(&mut self);
    fn publish(&mut self) {
        // Hide before metadata changes so a previous value cannot label a new item.
        if self.model.revealed.is_empty() {
            self.revealed.clear();
            self.revealed_changed();
        }
        self.snapshot = self.model.snapshot();
        self.revealed = self.model.revealed.clone();
        self.snapshot_changed();
        self.revealed_changed();
    }
    // Qt Bridge slots use the registered String metatype for borrowed arguments.
    #[allow(clippy::ptr_arg)]
    #[qslot]
    fn command(&mut self, action: &String, arg: &String) {
        if let Some(job) = self.model.command(action, arg) {
            let handle = self.get_thread_handle();
            self.model.launch(job, move |job| {
                handle.invoke_mut(move |this| {
                    this.model.complete(job);
                    this.publish();
                });
            });
        }
        self.publish();
    }
}
fn main() {
    let source = include_str!("../../qml/Main.qml").replace(
        "import PrototypeBackend",
        "import keychain_qtbridge_prototype",
    );
    let mut app = QApp::new();
    cxx_qt_lib::QGuiApplication::set_desktop_file_name(&"keychain-qt-prototype".into());
    let code = app.register::<Backend>().load_qml(source.as_bytes()).run();
    drop(app);
    std::process::exit(code);
}
