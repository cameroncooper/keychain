// Palette derivation adapted from Folio (MIT); see ../THIRD-PARTY-NOTICES.md.
use std::io::Read;
pub fn theme(light: bool) -> serde_json::Value {
    let mut colors = serde_json::json!({"background":if light{"#f4f3ef"}else{"#16161a"},
        "detail":if light{"#eae9e4"}else{"#111114"},"foreground":if light{"#29292e"}else{"#c8c8d0"},
        "bright":if light{"#202025"}else{"#ececf1"},"accent":if light{"#806400"}else{"#ffd60a"},"onAccent":"#16161a","radius":0});
    if let Some(home) = std::env::var_os("HOME") {
        let path =
            std::path::PathBuf::from(home).join(".local/state/omarchy/current/theme/colors.toml");
        if let Ok(input) = std::fs::File::open(path) {
            let mut file = String::new();
            if input.take(65537).read_to_string(&mut file).is_ok() && file.len() <= 65536 {
                for line in file.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        let key = key.trim();
                        let value = value.trim().trim_matches(['\'', '"']);
                        let target = match key {
                            "background" => "background",
                            "dark_background" => "detail",
                            "foreground" => "foreground",
                            "bright_foreground" => "bright",
                            "accent" => "accent",
                            _ => continue,
                        };
                        if value.len() == 7
                            && value.starts_with('#')
                            && value[1..].bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            colors[target] = value.into();
                        }
                    }
                }
            }
        }
    }
    let accent = colors["accent"].as_str().unwrap_or("#ffd60a");
    let background = colors["background"].as_str().unwrap_or("#16161a");
    let a = luminance(accent);
    let b = luminance(background);
    let contrast = (a.max(b) + 0.05) / (a.min(b) + 0.05);
    let selection = if contrast >= 4.5 {
        colors["accent"].clone()
    } else {
        colors["foreground"].clone()
    };
    let foreground = colors["foreground"].as_str().unwrap_or("#c8c8d0");
    colors["secondary"] = mix(background, foreground, 0.68).into();
    colors["selectionInk"] = selection;
    colors["onAccent"] = if a > 0.179 { "#000000" } else { "#ffffff" }.into();
    colors
}
// Folio derives secondary text from the base palette rather than per-widget opacity.
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
