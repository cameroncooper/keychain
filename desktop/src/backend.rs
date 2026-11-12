// Unsafe declarations are confined to CXX-Qt's generated Qt boundary.
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
        #[qproperty(QString, rows)]
        #[qproperty(QString, revealed)]
        type Backend = super::BackendRust;
        #[qinvokable]
        fn command(self: Pin<&mut Self>, action: &QString, arg: &QString);
    }
}
use cxx_qt::CxxQtType;
use cxx_qt_lib::QString;
use keychain::gui::controller::Controller;
use std::pin::Pin;
pub struct BackendRust {
    snapshot: QString,
    rows: QString,
    revealed: QString,
    controller: Controller,
    theme: serde_json::Value,
    rows_revision: u64,
    reveal_revision: u64,
}
impl Default for BackendRust {
    fn default() -> Self {
        let controller = Controller::default();
        let theme = crate::theme::theme(false);
        let mut state = controller.snapshot();
        state["theme"] = theme.clone();
        Self {
            snapshot: state.to_string().as_str().into(),
            rows: "[]".into(),
            revealed: "".into(),
            controller,
            theme,
            rows_revision: 0,
            reveal_revision: 0,
        }
    }
}
impl ffi::Backend {
    fn publish(mut self: Pin<&mut Self>) {
        // Create only Qt's presentation copy, borrowing the zeroizing Rust owner.
        let revealed = (self.rust().reveal_revision != self.rust().controller.reveal_revision())
            .then(|| QString::from(self.rust().controller.revealed()));
        let rows = (self.rust().rows_revision != self.rust().controller.rows_revision())
            .then(|| QString::from(self.rust().controller.rows().to_string().as_str()));
        let mut snapshot = self.rust().controller.snapshot();
        snapshot["theme"] = self.rust().theme.clone();
        let snapshot = QString::from(snapshot.to_string().as_str());
        // Clear the previous field before changing its binding/selection.
        if revealed.is_some() {
            self.as_mut().set_revealed("".into());
        }
        if let Some(rows) = rows {
            self.as_mut().rust_mut().rows_revision = self.rust().controller.rows_revision();
            if self.rust().rows != rows {
                self.as_mut().set_rows(rows);
            }
        }
        if self.rust().snapshot != snapshot {
            self.as_mut().set_snapshot(snapshot);
        }
        if let Some(revealed) = revealed {
            self.as_mut().rust_mut().reveal_revision = self.rust().controller.reveal_revision();
            self.set_revealed(revealed);
        }
    }
    pub fn command(mut self: Pin<&mut Self>, action: &QString, arg: &QString) {
        let action = action.to_string();
        let arg = arg.to_string();
        if action == "theme" {
            self.as_mut().rust_mut().theme = crate::theme::theme(arg == "light");
        } else {
            self.as_mut().rust_mut().controller.command(&action, &arg);
        }
        self.publish();
    }
}
