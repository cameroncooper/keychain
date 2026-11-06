//! GPUI presentation agent. Root-only socket requests; no SEP access or success grant.
use super::*;
use crate::prompt::{AgentEvent, DisplayEvent, Presentation, read_frame, write_frame};
use gpui_kit::assets::{AllAssets, IconName};
use gpui_kit::component::{
    Icon, Theme,
    button::{Button, ButtonVariants},
};
use gpui_kit::*;
use std::cell::RefCell;
use std::io;
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use uuid::Uuid;

enum Event {
    Begin(Presentation, UnixStream),
    Status(Uuid, String),
    End(Uuid),
}
struct Active {
    id: Uuid,
    window: AnyWindowHandle,
    view: Entity<AuthPrompt>,
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

/// Drop (including a window close) always shuts down the broker connection.
struct Channel {
    id: Uuid,
    stream: UnixStream,
}
impl Channel {
    fn cancel(&mut self) {
        let _ = write_frame(&mut self.stream, &AgentEvent::Cancel { id: self.id });
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.cancel();
    }
}
struct AuthPrompt {
    request: Presentation,
    status: String,
    channel: Rc<RefCell<Channel>>,
    focus: FocusHandle,
    first_frame: bool,
    presented: bool,
    was_active: bool,
    _activation: Subscription,
    _appearance: Subscription,
}
impl AuthPrompt {
    fn acknowledge_display(&mut self, window: &mut Window) {
        if self.presented || !self.first_frame || !window.is_visible() || !window.is_window_active()
        {
            return;
        }
        let mut channel = self.channel.borrow_mut();
        let id = channel.id;
        if write_frame(&mut channel.stream, &AgentEvent::Visible { id }).is_ok() {
            self.presented = true;
            self.was_active = true;
        } else {
            channel.cancel();
            window.remove_window();
        }
    }
}
impl Render for AuthPrompt {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = Palette::current(cx);
        div()
            .size_full()
            .flex()
            .flex_col()
            .rounded(px(16.))
            .overflow_hidden()
            .bg(rgb(palette.surface))
            .text_color(rgb(palette.text))
            .font_family("sans-serif")
            .text_size(px(13.))
            .track_focus(&self.focus)
            .on_key_down(|event, window, _| {
                if event.keystroke.key == "escape" {
                    window.remove_window();
                }
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .flex_shrink_0()
                    .mx_4()
                    .h(px(46.))
                    .border_b_1()
                    .border_color(rgb(palette.line))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(Icon::new(IconName::UserRound).size(px(16.)))
                            .child("Keychain"),
                    )
                    .child(
                        Button::new("cancel")
                            .label("Cancel")
                            .ghost()
                            .rounded(px(6.))
                            .h(px(24.))
                            .px_2()
                            .text_size(px(12.))
                            .bg(rgb(palette.tile))
                            .on_click(|_, window, _| window.remove_window()),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .id("prompt-content")
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .items_center()
                    .justify_center()
                    .px_8()
                    .py_5()
                    .child(
                        div()
                            .text_size(px(17.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_center()
                            .child("Use your fingerprint"),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_center()
                            .line_height(px(18.))
                            .child(display_text(&self.request.action)),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_center()
                            .text_color(rgb(palette.muted))
                            .child(display_text(&self.request.account)),
                    )
                    .child(
                        div().mt_4().mb_3().child(
                            Icon::default()
                                .data(include_bytes!("../../assets/fingerprint.svg"))
                                .text_color(rgb(palette.fingerprint))
                                .size(px(60.)),
                        ),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .line_height(px(17.))
                            .text_center()
                            .text_color(rgb(palette.muted))
                            .child(self.status.clone()),
                    ),
            )
    }
}

fn open_prompt(
    request: Presentation,
    stream: UnixStream,
    cx: &mut App,
) -> gpui_kit::Result<Active> {
    let id = request.id;
    let channel = Rc::new(RefCell::new(Channel { id, stream }));
    let close = channel.clone();
    let (window, view) = gpui_kit::open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(420.), px(290.)), cx)),
            titlebar: None,
            kind: WindowKind::Dialog,
            is_resizable: false,
            is_minimizable: false,
            app_id: Some("cameroncooper.keychain.Authentication".into()),
            ..Default::default()
        },
        cx,
        |window, cx| {
            window.on_window_should_close(cx, move |_, _| {
                close.borrow_mut().cancel();
                true
            });
            let view = cx.new(|cx| {
                let appearance = follow_system_appearance(window, cx);
                let focus = cx.focus_handle();
                window.focus(&focus, cx);
                let activation =
                    cx.observe_window_activation(window, |view: &mut AuthPrompt, window, _| {
                        if window.is_window_active() {
                            view.was_active = true;
                            view.acknowledge_display(window);
                        } else if view.was_active {
                            // Switching away ends this operation; returning never resumes capture.
                            view.channel.borrow_mut().cancel();
                            window.remove_window();
                        }
                    });
                AuthPrompt {
                    request,
                    channel,
                    focus,
                    status: "Preparing fingerprint reader…".into(),
                    first_frame: false,
                    presented: false,
                    was_active: window.is_window_active(),
                    _activation: activation,
                    _appearance: appearance,
                }
            });
            // Wait for a drawn frame AND focus before acknowledging presentation.
            let visible = view.downgrade();
            window.on_next_frame(move |window, _| {
                window.on_next_frame(move |window, cx| {
                    let _ = visible.update(cx, |view, _| {
                        view.first_frame = true;
                        view.acknowledge_display(window);
                    });
                });
                window.refresh();
            });
            view
        },
    )?;
    Ok(Active { id, window, view })
}

pub fn run() -> io::Result<()> {
    if keychain_sep_driver::peer::effective_uid() == 0 {
        return Err(io::Error::other(
            "agent must run in the unprivileged desktop session",
        ));
    }
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") else {
        eprintln!("XDG_RUNTIME_DIR is required");
        return Err(io::Error::other("agent socket setup failed"));
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
            return Err(io::Error::other("agent socket setup failed"));
        }
    };

    let (sender, receiver) = mpsc::sync_channel(16);
    std::thread::spawn(move || {
        if let Err(error) = listen(listener, sender) {
            eprintln!("keychain-auth-agent: {error}");
        }
    });
    gpui_kit::application()
        .with_quit_mode(QuitMode::Explicit)
        .with_assets(AllAssets)
        .run(move |cx| {
            gpui_kit::init(cx);
            Theme::sync_system_appearance(None, cx);
            let bus = match crate::prompt::activation::claim_name() {
                Ok(bus) => bus,
                Err(error) => {
                    eprintln!("keychain-auth-agent: {error}");
                    cx.quit();
                    return;
                }
            };
            cx.spawn(async move |cx| {
                let _lifetime = (_lock, bus);
                let mut active: Option<Active> = None;
                let mut last_activity = Instant::now();
                loop {
                    async_io::Timer::after(Duration::from_millis(25)).await;
                    let keep_running = cx.update(|cx| {
                        while let Ok(event) = receiver.try_recv() {
                            last_activity = Instant::now();
                            match event {
                                Event::Begin(request, stream) => {
                                    if active.is_some() {
                                        let _ = stream.shutdown(Shutdown::Both);
                                        continue;
                                    }
                                    match open_prompt(request, stream, cx) {
                                        Ok(prompt) => active = Some(prompt),
                                        Err(error) => eprintln!(
                                            "keychain-auth-agent: cannot display prompt: {error}"
                                        ),
                                    }
                                }
                                Event::Status(id, text) => {
                                    if let Some(current) = active.as_ref().filter(|a| a.id == id) {
                                        current.view.update(cx, |view, cx| {
                                            view.status = text;
                                            cx.notify();
                                        });
                                    }
                                }
                                Event::End(id) => {
                                    if active.as_ref().is_some_and(|a| a.id == id) {
                                        if let Some(current) = active.take() {
                                            let _ = current
                                                .window
                                                .update(cx, |_, w, _| w.remove_window());
                                        }
                                    }
                                }
                            }
                        }
                        // Some backends coalesce activation notifications around mapping.
                        // Also check current activation while an operation is displayed.
                        if let Some(current) = active.as_ref() {
                            let _ = current.window.update(cx, |_, window, cx| {
                                current.view.update(cx, |view, _| {
                                    if view.was_active && !window.is_window_active() {
                                        view.channel.borrow_mut().cancel();
                                        window.remove_window();
                                    }
                                });
                            });
                        }
                        // A closed window must cancel immediately, even while waiting for End.
                        if active
                            .as_ref()
                            .is_some_and(|a| a.window.update(cx, |_, _, _| ()).is_err())
                        {
                            if let Some(current) = active.take() {
                                current.view.read(cx).channel.borrow_mut().cancel();
                            }
                        }
                        if active.is_none() && last_activity.elapsed() >= Duration::from_secs(120) {
                            cx.quit();
                            return false;
                        }
                        true
                    });
                    if !keep_running {
                        break;
                    }
                }
            })
            .detach();
        });
    Ok(())
}
