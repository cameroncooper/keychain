//! Desktop credential browser. No SEP device access from the UI process.
fn main() {
    if let Err(error) = keychain_sep_driver::memory::make_process_nondumpable() {
        eprintln!("keychain-gui: could not protect process memory: {error}");
        std::process::exit(1);
    }
    if keychain_sep_driver::peer::effective_uid() == 0 {
        eprintln!("keychain-gui must run in your desktop session");
        std::process::exit(1);
    }
    keychain::desktop::app::run();
}
