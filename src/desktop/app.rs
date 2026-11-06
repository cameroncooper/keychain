//! Apple Passwords-inspired inventory and intentional field reveal.
use super::data::{Category, Item, load_items, now, reveal_field};
use super::*;
use crate::Result;
use crate::broker::login::{RevealField, RevealedLogin};
use gpui_kit::assets::{AllAssets, IconName};
use gpui_kit::base::{Button as TileButton, Disableable};
use gpui_kit::component::{
    Icon, Theme, ThemeMode, TitleBar,
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState},
};
use gpui_kit::prelude::FluentBuilder;
use gpui_kit::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

enum Update {
    Inventory(u64, Result<Vec<Item>>),
    Reveal(u64, Result<RevealedLogin>),
}
struct Passwords {
    items: Vec<Item>,
    selected: Option<String>,
    category: Category,
    search: Entity<InputState>,
    query: String,
    output: mpsc::Sender<Update>,
    generation: u64,
    inventory_generation: u64,
    canceled: Arc<AtomicBool>,
    busy: bool,
    loading: bool,
    error: Option<String>,
    revealed: Option<(RevealedLogin, Instant)>,
    awaiting_focus: Option<(RevealedLogin, Instant)>,
    _subscriptions: Vec<Subscription>,
}
impl Drop for Passwords {
    fn drop(&mut self) {
        self.canceled.store(true, Ordering::Release);
    }
}
impl Passwords {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Search"));
        let subscriptions = vec![
            cx.subscribe_in(&search, window, |this, input, event, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_reveal();
                    this.query = input.read(cx).value().to_string().trim().to_lowercase();
                    this.reconcile_selection();
                    cx.notify();
                }
            }),
            cx.observe_window_activation(window, |this, window, cx| {
                if !window.is_window_active() {
                    this.revealed = None;
                    cx.notify();
                }
            }),
        ];
        let (output, input) = mpsc::channel();
        cx.spawn_in(window, async move |weak, cx| {
            let mut last_second = now();
            loop {
                async_io::Timer::after(Duration::from_millis(100)).await;
                let second = now();
                let tick = second != last_second;
                last_second = second;
                if weak
                    .update_in(cx, |this, window, cx| {
                        while let Ok(update) = input.try_recv() {
                            match update {
                                Update::Inventory(generation, result)
                                    if generation == this.inventory_generation =>
                                {
                                    this.loading = false;
                                    match result {
                                        Ok(items) => {
                                            this.items = items;
                                            this.error = None;
                                            this.reconcile_selection();
                                        }
                                        Err(error) => {
                                            this.items.clear();
                                            this.selected = None;
                                            this.error = Some(error.to_string());
                                        }
                                    }
                                    cx.notify();
                                }
                                Update::Reveal(generation, result)
                                    if generation == this.generation =>
                                {
                                    match result {
                                        Ok(value) if !this.canceled.load(Ordering::Acquire) => {
                                            // The broker can deliver the result one frame before
                                            // the agent removes its window. Wait briefly for focus
                                            // to return; never render plaintext in an inactive app.
                                            this.awaiting_focus = Some((value, Instant::now()));
                                            this.error = None;
                                        }
                                        Ok(_) => {
                                            this.busy = false;
                                        }
                                        Err(error) => {
                                            this.busy = false;
                                            this.error = Some(error.to_string());
                                        }
                                    }
                                    cx.notify();
                                }
                                _ => {} // Stale replies (including secrets) are dropped and wiped.
                            }
                        }
                        if let Some((_, arrived)) = &this.awaiting_focus {
                            if arrived.elapsed() >= Duration::from_secs(2) {
                                this.awaiting_focus = None;
                                this.busy = false;
                                this.error =
                                    Some("Return to Keychain and choose Reveal again.".into());
                                cx.notify();
                            } else if window.is_window_active() {
                                this.revealed = this
                                    .awaiting_focus
                                    .take()
                                    .map(|(value, _)| (value, Instant::now()));
                                this.busy = false;
                                cx.notify();
                            }
                        }
                        if let Some((value, revealed_at)) = &this.revealed {
                            if tick && value.totp.is_some() {
                                cx.notify();
                            }
                            if revealed_at.elapsed() >= Duration::from_secs(30)
                                || value
                                    .totp
                                    .as_ref()
                                    .is_some_and(|code| code.expires <= now())
                            {
                                this.revealed = None;
                                cx.notify();
                            }
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        let mut this = Self {
            items: vec![],
            selected: None,
            category: Category::All,
            search,
            query: String::new(),
            output,
            generation: 0,
            inventory_generation: 0,
            canceled: Arc::new(AtomicBool::new(false)),
            busy: false,
            loading: false,
            error: None,
            revealed: None,
            awaiting_focus: None,
            _subscriptions: subscriptions,
        };
        this.refresh(cx);
        this
    }
    fn clear_reveal(&mut self) {
        self.canceled.store(true, Ordering::Release);
        self.canceled = Arc::new(AtomicBool::new(false));
        self.generation = self.generation.wrapping_add(1);
        self.busy = false;
        self.revealed = None;
        self.awaiting_focus = None;
    }
    fn refresh(&mut self, cx: &mut Context<Self>) {
        self.clear_reveal();
        self.loading = true;
        self.error = None;
        self.inventory_generation = self.inventory_generation.wrapping_add(1);
        let output = self.output.clone();
        let generation = self.inventory_generation;
        std::thread::spawn(move || {
            let _ = output.send(Update::Inventory(generation, load_items()));
        });
        cx.notify();
    }
    fn reconcile_selection(&mut self) {
        if !self.items.iter().any(|i| {
            self.selected.as_deref() == Some(&i.id) && i.matches(self.category, &self.query)
        }) {
            self.selected = self
                .items
                .iter()
                .find(|i| i.matches(self.category, &self.query))
                .map(|i| i.id.clone());
        }
    }
    fn reveal(&mut self, field: RevealField, cx: &mut Context<Self>) {
        let Some(item) = self
            .items
            .iter()
            .find(|i| self.selected.as_deref() == Some(&i.id))
            .cloned()
        else {
            return;
        };
        self.clear_reveal();
        self.error = None;
        self.busy = true;
        let output = self.output.clone();
        let generation = self.generation;
        let canceled = self.canceled.clone();
        std::thread::spawn(move || {
            let _ = output.send(Update::Reveal(
                generation,
                reveal_field(&item, field, canceled),
            ));
        });
        cx.notify();
    }
    fn category_tile(&self, category: Category, cx: &mut Context<Self>) -> impl IntoElement {
        let selected = self.category == category;
        let count = self.items.iter().filter(|i| category.contains(i)).count();
        TileButton::new(category.label())
            .accessibility_label(format!("{}: {} items", category.label(), count))
            .selected(selected)
            .disabled(self.loading)
            .text_left()
            .flex()
            .flex_col()
            .items_start()
            .gap_2()
            .p_3()
            .flex_1()
            .min_w_0()
            .h(px(96.))
            .rounded_xl()
            .bg(rgb(if selected { BLUE } else { 0xdedddf }))
            .cursor_pointer()
            .text_color(rgb(if selected { 0xffffff } else { TEXT }))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(icon_badge(
                        category.icon(),
                        if selected { 0x3487f6 } else { category.color() },
                        false,
                    ))
                    .child(div().text_size(px(19.)).child(count.to_string())),
            )
            .child(
                div()
                    .font_weight(FontWeight::MEDIUM)
                    .child(category.label()),
            )
            .on_click(cx.listener(move |this, _, _, cx| {
                if this.loading {
                    return;
                }
                this.clear_reveal();
                this.category = category;
                this.reconcile_selection();
                this.error = None;
                cx.notify();
            }))
    }
    fn field(&self, label: &'static str, value: String) -> impl IntoElement {
        div()
            .flex()
            .items_start()
            .justify_between()
            .gap_4()
            .py_4()
            .border_b_1()
            .border_color(rgb(LINE))
            .child(
                div()
                    .flex_shrink_0()
                    .font_weight(FontWeight::MEDIUM)
                    .child(label),
            )
            .child(
                div()
                    .min_w_0()
                    .text_right()
                    .text_color(rgb(MUTED))
                    .child(display_text(&value)),
            )
    }
    fn secret_row(
        &self,
        label: &'static str,
        field: RevealField,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let value = self.revealed.as_ref().and_then(|(v, _)| match field {
            RevealField::Password => v.password.as_ref().map(|p| p.to_string()),
            RevealField::Notes => v.notes.as_ref().map(|p| p.to_string()),
            RevealField::Totp => v
                .totp
                .as_ref()
                .map(|c| format!("{} · {}s", c.code, c.expires.saturating_sub(now()))),
            RevealField::All => None,
        });
        let visible = value.is_some();
        div()
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .py_3()
            .border_b_1()
            .border_color(rgb(LINE))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .min_w_0()
                    .child(label)
                    .child(
                        div()
                            .text_color(rgb(MUTED))
                            .child(value.unwrap_or_else(|| "••••••••".into())),
                    ),
            )
            .child(
                Button::new(label)
                    .label(if visible { "Hide" } else { "Reveal" })
                    .disabled(self.busy || self.loading)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if visible {
                            this.clear_reveal();
                            cx.notify();
                        } else {
                            this.reveal(field, cx);
                        }
                    })),
            )
    }
    fn details(&self, cx: &mut Context<Self>) -> AnyElement {
        let Some(item) = self
            .items
            .iter()
            .find(|i| self.selected.as_deref() == Some(&i.id))
        else {
            return div()
                .flex_1()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap_3()
                .text_color(rgb(MUTED))
                .child(Icon::new(IconName::KeyRound).size(px(42.)))
                .child(if self.loading {
                    "Loading credentials…"
                } else {
                    "Select a credential"
                })
                .into_any_element();
        };
        let mut card = div()
            .flex()
            .flex_col()
            .p_5()
            .rounded_xl()
            .border_1()
            .border_color(rgb(LINE))
            .bg(rgb(0xffffff))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_4()
                    .pb_5()
                    .child(icon_badge(item.icon(), item.color(), true))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .min_w_0()
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(23.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(display_text(&item.title)),
                            )
                            .child(div().text_color(rgb(MUTED)).child(if item.login.is_some() {
                                "Password"
                            } else {
                                "Passkey"
                            })),
                    ),
            )
            .child(self.field("Username", item.username.clone()))
            .child(self.field("Website", display_domain(&item.domain)));
        if let Some(login) = &item.login {
            if login.has_password {
                card = card.child(self.secret_row("Password", RevealField::Password, cx));
            }
            if login.has_totp {
                card = card.child(self.secret_row("Verification code", RevealField::Totp, cx));
            }
            if login.has_notes {
                card = card.child(self.secret_row("Notes", RevealField::Notes, cx));
            }
        }
        div().flex_1().min_w_0().h_full().id("credential-details").overflow_y_scroll().p_6().flex().flex_col().gap_5()
            .child(card)
            .child(div().flex().flex_col().gap_2().child(div().font_weight(FontWeight::SEMIBOLD).child("Storage & protection"))
                .child(div().p_4().rounded_xl().bg(rgb(0xf1f2f5)).flex().flex_col().gap_2()
                    .child(div().flex().gap_2().items_center().child(Icon::new(IconName::ShieldCheck)).child(item.storage))
                    .child(div().text_color(rgb(MUTED)).child(item.protection))))
            .child(div().text_size(px(12.)).text_color(rgb(MUTED)).child(if item.login.is_some() {
                "Revealed fields hide after 30 seconds or when this window loses focus."
            } else { "Use this passkey through the browser integration. Private keys are never displayed." }))
            .child(div().text_size(px(11.)).text_color(rgb(MUTED)).child(format!("ID  {}", item.id)))
            .into_any_element()
    }
}
impl Render for Passwords {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let compact = window.viewport_size().width < px(900.);
        let matches: Vec<_> = self
            .items
            .iter()
            .filter(|i| i.matches(self.category, &self.query))
            .collect();
        let body = div()
            .flex()
            .flex_1()
            .min_h_0()
            .w_full()
            .bg(rgb(BACKGROUND))
            .text_color(rgb(TEXT))
            .font_family("sans-serif")
            .text_size(px(14.))
            .on_key_down(cx.listener(|this, event: &KeyDownEvent, window, cx| {
                if event.keystroke.key == "escape" {
                    this.clear_reveal();
                    cx.notify();
                } else if event.keystroke.modifiers.control && event.keystroke.key == "f" {
                    this.search.read(cx).focus_handle(cx).focus(window, cx);
                }
            }))
            .when(!compact, |body| {
                body.child(
                    div()
                        .w(px(234.))
                        .flex_shrink_0()
                        .h_full()
                        .p_4()
                        .bg(rgb(SIDEBAR))
                        .border_r_1()
                        .border_color(rgb(LINE))
                        .flex()
                        .flex_col()
                        .gap_4()
                        .child(
                            div()
                                .pt_2()
                                .pb_2()
                                .text_size(px(21.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .child("Keychain"),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(self.category_tile(Category::All, cx))
                                .child(self.category_tile(Category::Passkeys, cx)),
                        )
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(self.category_tile(Category::Passwords, cx))
                                .child(self.category_tile(Category::Codes, cx)),
                        )
                        .child(div().flex_1())
                        .child(
                            Button::new("refresh")
                                .label("Refresh local items")
                                .disabled(self.loading || self.busy)
                                .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(MUTED))
                                .child("Sync with iCloud using keychain sync."),
                        ),
                )
            })
            .child(
                div()
                    .w(px(if compact { 240. } else { 310. }))
                    .flex_shrink_0()
                    .h_full()
                    .border_r_1()
                    .border_color(rgb(LINE))
                    .bg(rgb(0xffffff))
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .p_4()
                            .border_b_1()
                            .border_color(rgb(LINE))
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(Input::new(&self.search))
                            .child(
                                div()
                                    .flex()
                                    .justify_between()
                                    .child(
                                        div()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .child(self.category.label()),
                                    )
                                    .child(
                                        div()
                                            .text_color(rgb(MUTED))
                                            .child(format!("{} items", matches.len())),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .id("credential-list")
                            .overflow_y_scroll()
                            .p_2()
                            .children(matches.iter().map(|item| {
                                let id = item.id.clone();
                                let selected = self.selected.as_ref() == Some(&id);
                                TileButton::new(SharedString::from(id.clone()))
                                    .accessibility_label(format!(
                                        "{}, {}, {}",
                                        display_text(&item.title),
                                        display_text(&item.username),
                                        if item.login.is_some() {
                                            "password"
                                        } else {
                                            "passkey"
                                        }
                                    ))
                                    .selected(selected)
                                    .flex()
                                    .items_center()
                                    .gap_3()
                                    .p_3()
                                    .rounded_lg()
                                    .mb_1()
                                    .cursor_pointer()
                                    .bg(rgb(if selected { BLUE } else { 0xffffff }))
                                    .text_color(rgb(if selected { 0xffffff } else { TEXT }))
                                    .child(icon_badge(
                                        item.icon(),
                                        if selected { 0x3487f6 } else { item.color() },
                                        false,
                                    ))
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .flex()
                                            .flex_col()
                                            .gap_1()
                                            .child(
                                                div()
                                                    .truncate()
                                                    .font_weight(FontWeight::MEDIUM)
                                                    .child(display_text(&item.title)),
                                            )
                                            .child(
                                                div()
                                                    .truncate()
                                                    .text_size(px(12.))
                                                    .child(display_text(&item.username)),
                                            ),
                                    )
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.clear_reveal();
                                        this.selected = Some(id.clone());
                                        this.error = None;
                                        cx.notify();
                                    }))
                            }))
                            .when(matches.is_empty(), |d| {
                                d.child(div().p_4().text_color(rgb(MUTED)).child(if self.loading {
                                    "Loading…"
                                } else {
                                    "No matching credentials"
                                }))
                            }),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .flex()
                    .flex_col()
                    .when_some(self.error.as_ref(), |d, error| {
                        d.child(
                            div()
                                .p_4()
                                .bg(rgb(0xffeee9))
                                .text_color(rgb(0x943c25))
                                .child(display_text(error)),
                        )
                    })
                    .when(self.busy, |d| {
                        d.child(
                            div()
                                .px_6()
                                .py_3()
                                .text_color(rgb(MUTED))
                                .child("Waiting for the selected field…"),
                        )
                    })
                    .child(self.details(cx)),
            );
        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(BACKGROUND))
            .child(TitleBar::new().child("Keychain"))
            .when(compact, |outer| {
                outer.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .p_2()
                        .children(
                            [
                                Category::All,
                                Category::Passwords,
                                Category::Passkeys,
                                Category::Codes,
                            ]
                            .into_iter()
                            .map(|category| {
                                Button::new(category.label())
                                    .label(category.label())
                                    .when(self.category == category, |b| b.primary())
                                    .disabled(self.loading)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.clear_reveal();
                                        this.category = category;
                                        this.reconcile_selection();
                                        this.error = None;
                                        cx.notify();
                                    }))
                            }),
                        )
                        .child(
                            Button::new("compact-refresh")
                                .label("Refresh")
                                .disabled(self.loading || self.busy)
                                .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                        ),
                )
            })
            .child(body)
    }
}
pub fn run() {
    gpui_kit::application().with_assets(AllAssets).run(|cx| {
        gpui_kit::init(cx);
        Theme::change(ThemeMode::Light, None, cx);
        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        if let Err(error) = gpui_kit::open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::centered(size(px(1100.), px(710.)), cx)),
                window_min_size: Some(size(px(960.), px(540.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("Keychain".into()),
                    ..TitleBar::title_bar_options()
                }),
                app_id: Some("cameroncooper.keychain".into()),
                ..Default::default()
            },
            cx,
            |window, cx| cx.new(|cx| Passwords::new(window, cx)),
        ) {
            eprintln!("keychain-gui: cannot open window: {error}");
            cx.quit();
        }
    });
}
