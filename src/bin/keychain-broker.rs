use clap::{Parser, Subcommand};
use keychain::broker::{Broker, registry::Registry};
use keychain::security::sep::StoredSepKey;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(about = "Privileged selected-credential operation service")]
struct Cli {
    #[arg(long)]
    registry: PathBuf,
    /// Linux owner explicitly paired with the currently configured SEP identity.
    #[arg(long)]
    owner: u32,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Read-only account preflight using an already running enrolled worker.
    CheckAccount {
        #[arg(long, default_value_t=120, value_parser=clap::value_parser!(u64).range(1..=600))]
        timeout: u64,
    },
    /// Enroll an existing Octagon agreement key from an administrator PIPE.
    /// Does not sign in, generate a peer, fetch shares or write Apple records.
    ImportAccount {
        #[arg(long, value_parser=clap::value_parser!(u32).range(1..))]
        worker_uid: u32,
        #[arg(long, default_value = "/run/keychain-network/worker.sock")]
        worker_socket: PathBuf,
    },
    Serve {
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long, default_value = "/dev/sep-bio")]
        device: PathBuf,
        #[arg(long)]
        allow_diagnostics: bool,
        /// Enable only with the compatible local biometric item-decrypt driver.
        #[arg(long)]
        allow_item_decrypt: bool,
        /// Explicitly enable iCloud passkey writes after account/live validation.
        #[arg(long)]
        allow_synced_creation: bool,
        /// Exit once no request has been queued or active for this many seconds.
        #[arg(long,default_value_t=120,value_parser=clap::value_parser!(u64).range(1..=86400))]
        idle_timeout: u64,
    },
    /// Create the broker's item recipient using the compatible decrypt driver.
    PrepareItemKey {
        #[arg(long, default_value = "/dev/sep-bio")]
        device: PathBuf,
    },
    /// Explicitly enroll a disposable key in the diagnostic-only registry.
    ProvisionDiagnostic { key_file: PathBuf },
}
fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("keychain-broker: {error}");
        std::process::exit(1);
    }
}
fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if keychain_sep_driver::peer::effective_uid() != 0 || cli.owner == 0 {
        return Err(
            "broker requires root and an explicitly selected unprivileged SEP owner".into(),
        );
    }
    keychain_sep_driver::memory::make_process_nondumpable()?;
    if matches!(&cli.command, Command::Serve { socket: None, .. }) {
        verify_pairing(cli.owner, std::path::Path::new("/etc/keychain/sep-owner"))?;
    }
    if matches!(&cli.command, Command::CheckAccount { .. })
        && !cli
            .registry
            .join(format!("account-{}.enc", cli.owner))
            .try_exists()?
    {
        return Err("no enrolled account; account check will not initialize a registry".into());
    }
    let registry = Registry::open(&cli.registry)?;
    match cli.command {
        Command::CheckAccount { timeout } => {
            let result =
                registry.check_account(cli.owner, Instant::now() + Duration::from_secs(timeout))?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::ImportAccount {
            worker_uid,
            worker_socket,
        } => {
            use keychain::broker::account::{Bootstrap, MAX_BOOTSTRAP, WorkerSettings};
            use std::io::Read;
            keychain::paths::require_private_pipe(&std::io::stdin(), cli.owner)?;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(MAX_BOOTSTRAP as u64 + 1)
                .read_to_end(&mut bytes)?;
            let input = Bootstrap::decode(&bytes)?;
            let account = registry.enroll_account(
                cli.owner,
                &input,
                WorkerSettings {
                    uid: worker_uid,
                    socket: worker_socket,
                },
            )?;
            println!(
                "enrolled existing Octagon agreement identity for owner {} ({})",
                account.scope().owner,
                account.scope().account_fingerprint
            );
        }
        Command::PrepareItemKey { device } => {
            let mut device = keychain_sep_driver::Device::open(&device)?;
            println!(
                "{}",
                serde_json::to_string(&registry.provision_item_recipient(&mut device)?)?
            );
        }
        Command::ProvisionDiagnostic { key_file } => {
            let key = StoredSepKey::load(&key_file)?;
            println!("{}", registry.provision_diagnostic(cli.owner, key)?);
        }
        Command::Serve {
            socket,
            device,
            allow_diagnostics,
            allow_item_decrypt,
            allow_synced_creation,
            idle_timeout,
        } => {
            let mut activation = listenfd::ListenFd::from_env();
            let listener = if let Some(path) = socket {
                let listener = UnixListener::bind(&path)?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
                listener
            } else {
                activation
                    .take_unix_listener(0)?
                    .ok_or("no activation socket")?
            };
            let mut broker = Broker::new(registry, cli.owner, device, allow_diagnostics);
            broker.allow_item_decrypt = allow_item_decrypt;
            broker.allow_synced_creation = allow_synced_creation;
            serve(
                listener,
                Arc::new(broker),
                Duration::from_secs(idle_timeout),
            )?;
        }
    }
    Ok(())
}

fn pairing_matches(data: &[u8], owner: u32) -> bool {
    owner != 0 && data == format!("{owner}\n").as_bytes()
}
fn verify_pairing(owner: u32, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o077 != 0
        || meta.len() > 16
    {
        return Err("unsafe SEP owner pairing file".into());
    }
    let data = keychain::paths::read_bounded(path)?;
    if !pairing_matches(&data, owner) {
        return Err("activated broker owner does not match the explicitly paired SEP owner".into());
    }
    Ok(())
}

struct Activity {
    in_flight: AtomicUsize,
    last_finished: Mutex<Instant>,
}
impl Activity {
    fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            last_finished: Mutex::new(Instant::now()),
        }
    }
    fn begin(self: &Arc<Self>) -> ActivityGuard {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        ActivityGuard(self.clone())
    }
    fn idle(&self, now: Instant, timeout: Duration) -> bool {
        self.in_flight.load(Ordering::Acquire) == 0
            && self
                .last_finished
                .lock()
                .is_ok_and(|last| now.saturating_duration_since(*last) >= timeout)
    }
}
struct ActivityGuard(Arc<Activity>);
impl Drop for ActivityGuard {
    fn drop(&mut self) {
        if let Ok(mut last) = self.0.last_finished.lock() {
            *last = Instant::now();
        }
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve(
    listener: UnixListener,
    broker: Arc<Broker>,
    idle_timeout: Duration,
) -> std::io::Result<()> {
    use std::sync::mpsc::{TrySendError, sync_channel};
    listener.set_nonblocking(true)?;
    let activity = Arc::new(Activity::new());
    let (queue, pending) = sync_channel::<(std::os::unix::net::UnixStream, ActivityGuard)>(16);
    let pending = Arc::new(Mutex::new(pending));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let broker = broker.clone();
        let pending = pending.clone();
        workers.push(std::thread::spawn(move || {
            loop {
                let next = match pending.lock() {
                    Ok(queue) => queue.recv(),
                    Err(_) => return,
                };
                let Ok((mut stream, _activity)) = next else {
                    return;
                };
                if let Err(error) = broker.handle(&mut stream) {
                    eprintln!("keychain-broker: {error}");
                }
            }
        }));
    }
    let result = (|| loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if keychain_sep_driver::peer::credentials(&stream)?.uid != broker.owner {
                    continue;
                }
                // Count queued requests too. A full queue drops the new stream
                // and guard; owner traffic may postpone idle exit but cannot
                // grow an unbounded queue or bypass per-request deadlines.
                if let Err(TrySendError::Disconnected(_)) =
                    queue.try_send((stream, activity.begin()))
                {
                    return Err(std::io::Error::other("broker workers disconnected"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if activity.idle(Instant::now(), idle_timeout) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    })();
    drop(queue);
    for worker in workers {
        if worker.join().is_err() {
            return Err(std::io::Error::other("broker worker failed"));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activation_requires_the_exact_nonroot_paired_uid() {
        assert!(pairing_matches(b"1001\n", 1001));
        for invalid in [
            b"1002\n".as_slice(),
            b"01001\n",
            b"1001",
            b"1001\n1002\n",
            b"root\n",
            b"0\n",
        ] {
            assert!(!pairing_matches(invalid, 1001));
        }
        assert!(!pairing_matches(b"0\n", 0));
    }
    #[test]
    fn queued_and_active_requests_prevent_idle_exit_and_completion_resets_idle_clock() {
        let activity = Arc::new(Activity::new());
        let timeout = Duration::from_secs(120);
        let future = Instant::now() + timeout + Duration::from_secs(1);
        assert!(activity.idle(future, timeout));
        let first = activity.begin();
        let second = activity.begin();
        assert!(!activity.idle(future, timeout));
        drop(first);
        assert!(!activity.idle(future, timeout));
        drop(second);
        assert!(!activity.idle(Instant::now(), timeout));
        assert!(activity.idle(Instant::now() + timeout, timeout));
    }
    #[test]
    #[ignore = "requires root for a temporary private registry; no SEP access"]
    fn listener_exits_after_idle_but_waits_for_an_incomplete_request_to_disconnect() {
        use std::io::Write;
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("mode: {e}"));
        let registry = Registry::open(directory.path()).unwrap_or_else(|e| panic!("registry: {e}"));
        // This test's root client is paired only with its synthetic in-process
        // broker. The executable still refuses UID 0 as a configured owner.
        let broker = Arc::new(Broker::new(
            registry,
            0,
            "/dev/does-not-exist".into(),
            false,
        ));
        let path = directory.path().join("test.sock");
        let listener = UnixListener::bind(&path).unwrap_or_else(|e| panic!("bind: {e}"));
        let mut client = std::os::unix::net::UnixStream::connect(&path)
            .unwrap_or_else(|e| panic!("connect: {e}"));
        client
            .write_all(&[1])
            .unwrap_or_else(|e| panic!("partial header: {e}"));
        let (done, result) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let outcome = serve(listener, broker, Duration::from_millis(100));
            let _ = done.send(outcome);
        });
        assert!(matches!(
            result.recv_timeout(Duration::from_millis(250)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(client);
        result
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|e| panic!("idle exit: {e}"))
            .unwrap_or_else(|e| panic!("serve: {e}"));
        worker.join().unwrap_or_else(|_| panic!("worker panicked"));
    }
}
