// Palette reading, derivation and Hyprland rounding adapted from Folio (MIT);
// see ../THIRD-PARTY-NOTICES.md.
//
// Every Omarchy color the file names is passed on, so components can use the
// theme's own red or blue instead of inventing one. Without Omarchy, a neutral
// palette follows Qt's light/dark preference. Appearance never affects
// authorization.
use serde_json::{Map, Value, json};
use std::io::{Read, Write};
use std::time::Duration;

/// Folio's fallback, plus light counterparts chosen for 4.5:1 on the light surface.
fn fallback(light: bool) -> Value {
    if light {
        json!({"background":"#f4f3ef","dark_background":"#eae9e4","lighter_background":"#ffffff",
            "foreground":"#29292e","bright_foreground":"#202025","accent":"#806400",
            "red":"#b3261e","yellow":"#7a5a00","green":"#2e6b30","blue":"#2357b5",
            "magenta":"#7b3fa6","cyan":"#0e6a80","orange":"#a04a00"})
    } else {
        json!({"background":"#16161a","dark_background":"#111114","lighter_background":"#232329",
            "foreground":"#c8c8d0","bright_foreground":"#ececf1","accent":"#ffd60a",
            "red":"#f7768e","yellow":"#e0af68","green":"#9ece6a","blue":"#7aa2f7",
            "magenta":"#bb9af7","cyan":"#7dcfff","orange":"#ff9e64"})
    }
}

/// `light` is Qt's platform preference, used only when Omarchy says nothing.
/// `radius` is the compositor's window rounding, when known.
pub fn theme(light: bool, radius: Option<u32>) -> Value {
    let (colors, mode) = read_omarchy();
    // Omarchy's own mode wins; a theme without one is judged by its background.
    let light = mode.unwrap_or_else(|| {
        colors
            .get("background")
            .and_then(Value::as_str)
            .map_or(light, |bg| luminance(bg) > 0.5)
    });
    let mut palette = fallback(light);
    let mut has_background = false;
    for (key, value) in colors {
        has_background |= key == "background";
        palette[key] = value;
    }
    // A theme without its own background is incomplete; don't mix its
    // foreground with our fallback surface.
    if !has_background {
        palette = fallback(light);
    }
    let get = |key: &str| palette[key].as_str().unwrap_or("#888888").to_string();
    let background = get("background");
    let foreground = get("foreground");
    let accent = get("accent");
    let lighter = if (luminance(&get("lighter_background")) - luminance(&background)).abs() > 0.004
    {
        get("lighter_background")
    } else {
        mix(&background, &foreground, 0.08)
    };
    let a = luminance(&accent);
    let b = luminance(&background);
    let contrast = (a.max(b) + 0.05) / (a.min(b) + 0.05);
    json!({
        "light": light,
        "background": background,
        "detail": get("dark_background"),
        "lighter": lighter,
        "foreground": foreground,
        "bright": get("bright_foreground"),
        // Folio derives secondary text rather than trusting a theme's dim color.
        "secondary": mix(&background, &foreground, 0.68),
        "accent": accent,
        "onAccent": if a > 0.179 { "#000000" } else { "#ffffff" },
        // An accent too faint on the surface shouldn't carry selected text.
        "selectionInk": if contrast >= 4.5 { accent.clone() } else { get("bright_foreground") },
        "red": get("red"), "yellow": get("yellow"), "green": get("green"), "blue": get("blue"),
        "magenta": get("magenta"), "cyan": get("cyan"), "orange": get("orange"),
        "radius": radius.unwrap_or(0).min(24),
    })
}

fn read_omarchy() -> (Map<String, Value>, Option<bool>) {
    let mut colors = Map::new();
    let Some(home) = std::env::var_os("HOME") else {
        return (colors, None);
    };
    let path =
        std::path::PathBuf::from(home).join(".local/state/omarchy/current/theme/colors.toml");
    let Ok(input) = std::fs::File::open(path) else {
        return (colors, None);
    };
    let mut file = String::new();
    if input.take(65537).read_to_string(&mut file).is_err() || file.len() > 65536 {
        return (colors, None);
    }
    let mut mode = None;
    for line in file.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches(['\'', '"']);
        if key == "mode" {
            mode = Some(value == "light");
        } else if key.len() <= 32
            && key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            && value.len() == 7
            && value.starts_with('#')
            && value[1..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            colors.insert(key.into(), value.to_ascii_lowercase().into());
        }
    }
    (colors, mode)
}

/// Hyprland's effective `decoration:rounding`, asked over its request socket
/// (what `hyprctl -j getoption` does) with short timeouts, since this runs on
/// the UI thread. Without Hyprland the corners stay square, like Omarchy's default.
pub fn hyprland_rounding() -> Option<u32> {
    let signature = std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE")?;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
    let socket = std::path::PathBuf::from(runtime)
        .join("hypr")
        .join(signature)
        .join(".socket.sock");
    let mut stream = std::os::unix::net::UnixStream::connect(socket).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(100)))
        .ok()?;
    stream.write_all(b"j/getoption decoration:rounding").ok()?;
    let mut reply = String::new();
    stream.take(4096).read_to_string(&mut reply).ok()?;
    let value: Value = serde_json::from_str(&reply).ok()?;
    u32::try_from(value.get("int")?.as_i64()?).ok()
}

fn mix(background: &str, foreground: &str, amount: f64) -> String {
    let bg = u32::from_str_radix(background.trim_start_matches('#'), 16).unwrap_or(0);
    let fg = u32::from_str_radix(foreground.trim_start_matches('#'), 16).unwrap_or(0);
    let channel = |shift: u32| {
        (((bg >> shift) & 255) as f64 * (1.0 - amount) + ((fg >> shift) & 255) as f64 * amount)
            .round() as u8
    };
    format!("#{:02x}{:02x}{:02x}", channel(16), channel(8), channel(0))
}
fn luminance(hex: &str) -> f64 {
    let rgb = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0);
    let linear = |shift: u32| {
        let v = ((rgb >> shift) & 255u32) as f64 / 255.0;
        if v <= 0.04045 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(16) + 0.7152 * linear(8) + 0.0722 * linear(0)
}
