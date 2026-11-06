use clap::{Parser, Subcommand};
use keychain::apple::worker::service::{self, Credentials, ServiceConfig};
use keychain::config::Config;
use keychain::paths::{AppPaths, StateLock, read_bounded};
use keychain::security::{RootKeySource, SoftwareFileBackend};
use keychain::store::StateStore;
use keychain::{Error, Result};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Account-scoped Apple HTTP worker; no SEP or browser socket access")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "/var/lib/keychain-network")]
        state_directory: PathBuf,
        #[arg(long, default_value = "/run/keychain-network")]
        runtime_directory: PathBuf,
        #[arg(long, default_value = "/usr/libexec/keychain/keychain-anisette-mac")]
        helper: PathBuf,
        #[arg(long, default_value = "/usr/lib/keychain/CoreADI")]
        coreadi: PathBuf,
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=86400))]
        idle_timeout: u64,
    },
    /// Export minimal credentials from the existing local profile to a PIPE.
    /// Pipe directly to sudo systemd-creds encrypt; never write plaintext to disk.
    Export,
    /// Validate systemd-supplied credentials without helper startup or Apple IO.
    CheckCredentials,
}
struct ExistingRoot(PathBuf);
impl RootKeySource for ExistingRoot {
    fn root_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let bytes = Zeroizing::new(read_bounded(&self.0)?);
        let mut root = Zeroizing::new([0; 32]);
        if bytes.len() != root.len() {
            return Err(Error::Security(
                "invalid existing root; refusing replacement".into(),
            ));
        }
        root.copy_from_slice(&bytes);
        Ok(root)
    }
}
fn credentials_directory() -> Result<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or_else(|| {
            Error::Config("start this worker through its systemd service credentials".into())
        })
}
fn export() -> Result<()> {
    let owner = keychain_sep_driver::peer::effective_uid();
    if owner == 0 || std::io::stdout().is_terminal() {
        return Err(Error::Refused("run export as the profile owner and pipe directly to sudo systemd-creds encrypt --with-key=host --name=network-account - OUTPUT".into()));
    }
    let paths = AppPaths::discover()?;
    let _lock = StateLock::acquire(&paths)?;
    let config = Config::load(&paths)?;
    if config.security_backend != "software-file" {
        return Err(Error::Config(
            "export requires the selected existing account backend".into(),
        ));
    }
    let backend = SoftwareFileBackend::with_root_source(
        paths.clone(),
        Box::new(ExistingRoot(paths.software_key_file())),
    );
    let store = StateStore::new(&paths, &backend);
    let account = store.load_account()?.ok_or_else(|| {
        Error::AuthenticationRequired("sign in locally before exporting worker credentials".into())
    })?;
    let device = store
        .load_device()?
        .ok_or_else(|| Error::Config("existing device identity missing".into()))?;
    let peer = store
        .load_octagon()?
        .ok_or_else(|| Error::Config("existing joined peer missing".into()))?;
    let seed = Zeroizing::new(read_bounded(
        &paths.anisette_dir().join("macos/machine.json"),
    )?);
    let credentials = Credentials::from_account(owner, &account, &device, &peer, &seed)?;
    std::io::stdout()
        .lock()
        .write_all(&credentials.encode()?)
        .map_err(|e| Error::io("encrypted-credential input pipe", e))
}
fn run(cli: Cli) -> Result<()> {
    keychain_sep_driver::memory::make_process_nondumpable()
        .map_err(|e| Error::io("worker memory policy", e))?;
    match cli.command {
        Command::Export => export(),
        Command::CheckCredentials => {
            service::load_credentials(&credentials_directory()?)?;
            println!("worker credentials validated; no helper or Apple request started");
            Ok(())
        }
        Command::Serve {
            state_directory,
            runtime_directory,
            helper,
            coreadi,
            idle_timeout,
        } => service::run(ServiceConfig {
            credentials_directory: credentials_directory()?,
            state_directory,
            runtime_directory,
            helper,
            coreadi,
            idle_timeout: Duration::from_secs(idle_timeout),
        }),
    }
}
fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("keychain-network-worker: {error}");
        std::process::exit(1);
    }
}
