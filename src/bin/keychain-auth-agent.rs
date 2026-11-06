//! Unprivileged desktop presentation agent. It never opens the SEP device.
fn main() {
    if let Err(error) = keychain::desktop::auth::run() {
        eprintln!("keychain-auth-agent: {error}");
        std::process::exit(1);
    }
}
