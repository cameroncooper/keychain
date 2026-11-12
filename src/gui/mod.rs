//! Toolkit-independent credential inventory and deliberate field presentation.
pub mod controller;
mod data;
mod text;
pub use data::{Category, Item, load_items, now, reveal_field};
pub use text::{display_domain, display_text};
