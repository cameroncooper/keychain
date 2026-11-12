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
