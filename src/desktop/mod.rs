//! Unprivileged desktop presentation. The broker retains all authorization policy.
pub mod app;
pub mod auth;
mod data;

use gpui_kit::assets::IconName;
use gpui_kit::component::Icon;
use gpui_kit::*;

pub const BACKGROUND: u32 = 0xfafafa;
pub const SIDEBAR: u32 = 0xeeedee;
pub const TEXT: u32 = 0x242428;
pub const MUTED: u32 = 0x737379;
pub const LINE: u32 = 0xe4e4e8;
pub const BLUE: u32 = 0x0969ef;

pub fn icon_badge(name: IconName, color: u32, large: bool) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_center()
        .size(px(if large { 64. } else { 36. }))
        .rounded(px(if large { 16. } else { 9. }))
        .bg(rgb(color))
        .text_color(rgb(0xffffff))
        .child(Icon::new(name).size(px(if large { 30. } else { 19. })))
}

/// Plain text only. Strip controls and bidirectional format overrides from
/// account-supplied metadata; domain rows additionally use URL's ASCII host form.
pub fn display_text(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(1024)
        .collect()
}

pub fn display_domain(value: &str) -> String {
    let url = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    match url::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
    {
        Some(host) => host,
        None => display_text(value),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn display_metadata_cannot_inject_controls_or_bidi_overrides() {
        assert_eq!(
            super::display_text("alice\n\u{202e}moc.elpmaxe"),
            "alicemoc.elpmaxe"
        );
        assert_eq!(
            super::display_domain("https://example.com@evil.com/path"),
            "evil.com"
        );
        assert_eq!(
            super::display_domain("bücher.example"),
            "xn--bcher-kva.example"
        );
        assert_eq!(super::display_text(&"x".repeat(2048)).len(), 1024);
    }
}
