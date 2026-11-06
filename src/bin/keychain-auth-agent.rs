//! Unprivileged desktop presentation agent. It never opens the SEP device.
use std::cell::RefCell;
use std::io;
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use gtk4::{gio, glib, prelude::*};
use keychain::prompt::{AgentEvent, DisplayEvent, Presentation, read_frame, write_frame};
use uuid::Uuid;

enum Event {
    Begin(Presentation, UnixStream),
    Status(Uuid, String),
    End(Uuid),
}
struct Active {
    id: Uuid,
    window: gtk4::ApplicationWindow,
    status: gtk4::Label,
}

fn listen(listener: UnixListener, output: mpsc::SyncSender<Event>) -> io::Result<()> {
    for connection in listener.incoming() {
        let stream = connection?;
        if keychain_sep_driver::peer::credentials(&stream)?.uid != 0 {
            continue;
        }
        let output = output.clone();
        std::thread::spawn(move || {
            let mut input = stream;
            let _ = input.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = input.set_write_timeout(Some(Duration::from_secs(1)));
            let mut active_id = None;
            let _result = (|| -> io::Result<()> {
                let DisplayEvent::Present {
                    version: 1,
                    request,
                } = read_frame(&mut input)?
                else {
                    return Err(io::Error::other("expected presentation"));
                };
                request.validate()?;
                let id = request.id;
                active_id = Some(id);
                output
                    .send(Event::Begin(request, input.try_clone()?))
                    .map_err(io::Error::other)?;
                // All real operations have an upper bound, including forgotten UI.
                input.set_read_timeout(Some(Duration::from_secs(125)))?;
                loop {
                    match read_frame(&mut input)? {
                        DisplayEvent::Status {
                            id: received,
                            message,
                        } if received == id
                            && message.len() <= 512
                            && !message.chars().any(char::is_control) =>
                        {
                            output
                                .send(Event::Status(id, message))
                                .map_err(io::Error::other)?;
                        }
                        DisplayEvent::Finished { id: received } if received == id => return Ok(()),
                        _ => return Err(io::Error::other("invalid operation status")),
                    }
                }
            })();
            // On read failure terminate the operation and remove its window.
            let _ = input.shutdown(Shutdown::Both);
            if let Some(id) = active_id {
                let _ = output.send(Event::End(id));
            }
        });
    }
    Ok(())
}

fn main() -> glib::ExitCode {
    if keychain_sep_driver::peer::effective_uid() == 0 {
        eprintln!("keychain-auth-agent must run in the unprivileged desktop session");
        return glib::ExitCode::FAILURE;
    }
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") else {
        eprintln!("XDG_RUNTIME_DIR is required");
        return glib::ExitCode::FAILURE;
    };
    let path = PathBuf::from(runtime).join("keychain-auth.sock");
    let runtime = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/nonexistent"));
    let prepare = (|| -> io::Result<(std::fs::File, UnixListener)> {
        let meta = std::fs::symlink_metadata(runtime)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != keychain_sep_driver::peer::effective_uid()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::other("unsafe runtime directory"));
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(runtime.join("keychain-auth.lock"))?;
        let meta = lock.metadata()?;
        if !meta.is_file()
            || meta.uid() != keychain_sep_driver::peer::effective_uid()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::other("unsafe agent lock"));
        }
        fs2::FileExt::try_lock_exclusive(&lock)?;
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket()
                || meta.uid() != keychain_sep_driver::peer::effective_uid()
            {
                return Err(io::Error::other("unsafe existing agent socket"));
            }
            // Agents hold the lock; this socket can only be stale.
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok((lock, listener))
    })();
    let (_lock, listener) = match prepare {
        Ok(value) => value,
        Err(error) => {
            eprintln!("keychain-auth-agent: {error}");
            return glib::ExitCode::FAILURE;
        }
    };
    let (sender, receiver) = mpsc::sync_channel(16);
    std::thread::spawn(move || {
        if let Err(error) = listen(listener, sender) {
            eprintln!("keychain-auth-agent: {error}");
        }
    });
    let app = gtk4::Application::new(
        Some("cameroncooper.keychain.Authentication"),
        gio::ApplicationFlags::NON_UNIQUE,
    );
    let _hold = app.hold();
    let active: Rc<RefCell<Option<Active>>> = Rc::new(RefCell::new(None));
    let application = app.clone();
    glib::timeout_add_local(Duration::from_millis(25), move || {
        while let Ok(event) = receiver.try_recv() {
            match event {
                Event::Begin(request, stream) => {
                    if active.borrow().is_some() {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    let window = gtk4::ApplicationWindow::builder()
                        .application(&application)
                        .title("Authentication required")
                        .default_width(420)
                        .resizable(false)
                        .modal(true)
                        .build();
                    let layout = gtk4::Box::new(gtk4::Orientation::Vertical, 14);
                    layout.set_margin_top(28);
                    layout.set_margin_bottom(24);
                    layout.set_margin_start(28);
                    layout.set_margin_end(28);
                    let icon = gtk4::Image::from_icon_name("fingerprint-symbolic");
                    icon.set_pixel_size(56);
                    let app_label = gtk4::Label::new(Some(&request.application));
                    let title = gtk4::Label::new(Some(&request.action));
                    title.set_wrap(true);
                    title.add_css_class("title-3");
                    let account = gtk4::Label::new(Some(&request.account));
                    account.set_wrap(true);
                    let status = gtk4::Label::new(Some("Preparing fingerprint reader…"));
                    status.set_wrap(true);
                    let cancel = gtk4::Button::with_label("Cancel");
                    for widget in [
                        &icon.clone().upcast::<gtk4::Widget>(),
                        &app_label.upcast(),
                        &title.upcast(),
                        &account.upcast(),
                        &status.clone().upcast(),
                        &cancel.clone().upcast(),
                    ] {
                        layout.append(widget);
                    }
                    window.set_child(Some(&layout));
                    let writer = Rc::new(RefCell::new(stream));
                    let id = request.id;
                    let mapped = writer.clone();
                    window.connect_map(move |_| {
                        let _ = write_frame(&mut mapped.borrow_mut(), &AgentEvent::Visible { id });
                    });
                    let canceled = writer.clone();
                    window.connect_close_request(move |_| {
                        let _ = write_frame(&mut canceled.borrow_mut(), &AgentEvent::Cancel { id });
                        let _ = canceled.borrow().shutdown(Shutdown::Both);
                        glib::Propagation::Proceed
                    });
                    let close = window.clone();
                    cancel.connect_clicked(move |_| close.close());
                    let keys = gtk4::EventControllerKey::new();
                    let close = window.clone();
                    keys.connect_key_pressed(move |_, key, _, _| {
                        if key == gtk4::gdk::Key::Escape {
                            close.close();
                            glib::Propagation::Stop
                        } else {
                            glib::Propagation::Proceed
                        }
                    });
                    window.add_controller(keys);
                    *active.borrow_mut() = Some(Active {
                        id,
                        window: window.clone(),
                        status,
                    });
                    window.present();
                }
                Event::Status(id, text) => {
                    if let Some(current) = active.borrow().as_ref().filter(|a| a.id == id) {
                        current.status.set_text(&text);
                    }
                }
                Event::End(id) => {
                    if active.borrow().as_ref().is_some_and(|a| a.id == id) {
                        if let Some(current) = active.borrow_mut().take() {
                            current.window.close();
                        }
                    }
                }
            }
        }
        glib::ControlFlow::Continue
    });
    app.connect_activate(|_| {});
    app.run()
}
