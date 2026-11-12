#[cxx_qt::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }
    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, snapshot)]
        #[qproperty(QString, revealed)]
        type Backend = super::BackendRust;
        #[qinvokable]
        fn command(self: Pin<&mut Self>, action: &QString, arg: &QString);
    }
    impl cxx_qt::Threading for Backend {}
}
use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::QString;
use std::pin::Pin;
pub struct BackendRust {
    snapshot: QString,
    revealed: QString,
    model: prototype_model::Model,
}
impl Default for BackendRust {
    fn default() -> Self {
        let model = prototype_model::Model::default();
        Self {
            snapshot: model.snapshot().as_str().into(),
            revealed: "".into(),
            model,
        }
    }
}
impl ffi::Backend {
    fn publish(mut self: Pin<&mut Self>) {
        let snapshot = self.rust().model.snapshot();
        let revealed = self.rust().model.revealed.clone();
        // Clear a hidden value before publishing a new selection.
        if revealed.is_empty() {
            self.as_mut().set_revealed("".into());
        }
        self.as_mut().set_snapshot(snapshot.as_str().into());
        self.set_revealed(revealed.as_str().into());
    }
    pub fn command(mut self: Pin<&mut Self>, action: &QString, arg: &QString) {
        if let Some(job) = self
            .as_mut()
            .rust_mut()
            .model
            .command(&action.to_string(), &arg.to_string())
        {
            let handle = self.qt_thread();
            self.as_mut().rust_mut().model.launch(job, move |job| {
                let _ = handle.queue(move |mut this| {
                    this.as_mut().rust_mut().model.complete(job);
                    this.publish();
                });
            });
        }
        self.publish();
    }
}
