//! Unprivileged desktop presentation. The broker retains all authorization policy.
pub mod auth;

use gpui_kit::*;

pub const BACKGROUND: u32 = 0xfafafa;
pub const SIDEBAR: u32 = 0xeeedee;
pub const TEXT: u32 = 0x242428;
pub const MUTED: u32 = 0x737379;
pub const LINE: u32 = 0xe4e4e8;
pub const BLUE: u32 = 0x0969ef;

pub use crate::gui::{display_domain, display_text};

/// GPUI's Linux backend reads org.freedesktop.appearance/color-scheme through
/// XDG Desktop Portal and forwards SettingChanged as window appearance changes.
/// Keep this policy in the unprivileged UI; the broker does not consult it.
pub fn follow_system_appearance<T: 'static>(
    window: &mut Window,
    cx: &mut Context<T>,
) -> Subscription {
    gpui_kit::component::Theme::sync_system_appearance(Some(window), cx);
    cx.observe_window_appearance(window, |_, window, cx| {
        gpui_kit::component::Theme::sync_system_appearance(Some(window), cx);
    })
}

#[derive(Clone, Copy)]
pub struct Palette {
    pub background: u32,
    pub surface: u32,
    pub sidebar: u32,
    pub tile: u32,
    pub text: u32,
    pub muted: u32,
    pub line: u32,
    pub inset: u32,
    pub error_background: u32,
    pub error_text: u32,
    pub fingerprint: u32,
}
impl Palette {
    pub fn current(cx: &App) -> Self {
        use gpui_kit::component::ActiveTheme;
        if cx.theme().mode.is_dark() {
            Self {
                background: 0x202023,
                surface: 0x29292d,
                sidebar: 0x252528,
                tile: 0x39393f,
                text: 0xf4f4f6,
                muted: 0xb0b0b8,
                line: 0x404046,
                inset: 0x303035,
                error_background: 0x492a29,
                error_text: 0xffb6a9,
                fingerprint: 0xe998b3,
            }
        } else {
            Self {
                background: BACKGROUND,
                surface: 0xfdfdfd,
                sidebar: SIDEBAR,
                tile: 0xdedddf,
                text: TEXT,
                muted: MUTED,
                line: LINE,
                inset: 0xf1f2f5,
                error_background: 0xffeee9,
                error_text: 0x943c25,
                fingerprint: 0xcd7691,
            }
        }
    }
}
