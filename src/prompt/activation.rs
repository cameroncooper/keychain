//! User-side D-Bus lifecycle only. Bus ownership/startup never authorizes SEP use.
use std::future::Future;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const AGENT_BUS_NAME: &str = "cameroncooper.keychain.AuthenticationAgent";
const START_TIMEOUT: Duration = Duration::from_secs(5);

fn runtime(owner: u32) -> io::Result<PathBuf> {
    if owner == 0 || owner != keychain_sep_driver::peer::effective_uid() {
        return Err(io::Error::other(
            "agent activation requires the desktop owner's UID",
        ));
    }
    let path = PathBuf::from(format!("/run/user/{owner}"));
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::other(
            "unsafe agent activation runtime directory",
        ));
    }
    Ok(path)
}
async fn socket_ready(path: &Path, owner: u32) -> io::Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::other(
            "unsafe prompt socket; refusing activation",
        ));
    }
    let stream = match async_io::Async::<UnixStream>::connect(path).await {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    if keychain_sep_driver::peer::credentials(stream.get_ref())?.uid != owner {
        return Err(io::Error::other("wrong prompt-agent owner"));
    }
    Ok(true)
}
fn bounded<T>(
    query: impl Future<Output = io::Result<T>>,
    canceled: &AtomicBool,
    timeout: Duration,
) -> io::Result<T> {
    async_io::block_on(futures_lite::future::or(
        async {
            if canceled.load(Ordering::Acquire) {
                return Err(canceled_error());
            }
            let value = query.await?;
            if canceled.load(Ordering::Acquire) {
                return Err(canceled_error());
            }
            Ok(value)
        },
        async {
            let deadline = Instant::now() + timeout;
            loop {
                if canceled.load(Ordering::Acquire) {
                    return Err(canceled_error());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "desktop agent activation timed out",
                    ));
                }
                async_io::Timer::after(Duration::from_millis(20)).await;
            }
        },
    ))
}
fn canceled_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "desktop agent activation canceled",
    )
}
fn failed(error: zbus::Error) -> io::Error {
    io::Error::other(format!("desktop agent activation: {error}"))
}
fn bus_address(runtime: &Path, owner: u32) -> io::Result<String> {
    let path = runtime.join("bus");
    let metadata = std::fs::symlink_metadata(&path)?;
    // The bus socket is commonly mode 0666, inside its checked private directory.
    if !metadata.file_type().is_socket() || metadata.uid() != owner {
        return Err(io::Error::other("unsafe session bus socket"));
    }
    Ok(format!("unix:path={}", path.display()))
}

/// Activate only in the calling desktop user's bus, ignoring environment-supplied
/// bus addresses. Actual prompt peer/presentation checks remain broker-owned.
pub(crate) fn ensure_running(canceled: &AtomicBool) -> io::Result<()> {
    let owner = keychain_sep_driver::peer::effective_uid();
    let runtime = runtime(owner)?;
    let path = runtime.join("keychain-auth.sock");
    if canceled.load(Ordering::Acquire) {
        return Err(canceled_error());
    }
    bounded(
        async {
            if socket_ready(&path, owner).await? {
                return Ok(());
            }
            let address = bus_address(&runtime, owner)?;
            let bus = zbus::connection::Builder::address(address.as_str())
                .map_err(failed)?
                .build()
                .await
                .map_err(failed)?;
            let reply = bus
                .call_method(
                    Some("org.freedesktop.DBus"),
                    "/org/freedesktop/DBus",
                    Some("org.freedesktop.DBus"),
                    "StartServiceByName",
                    &(AGENT_BUS_NAME, 0u32),
                )
                .await
                .map_err(failed)?;
            let outcome: u32 = reply.body().deserialize().map_err(failed)?;
            if !matches!(outcome, 1 | 2) || !socket_ready(&path, owner).await? {
                return Err(io::Error::other(
                    "desktop agent started without a valid prompt socket",
                ));
            }
            Ok(())
        },
        canceled,
        START_TIMEOUT,
    )
}

/// Called after GPUI initialization and listener setup. Holding this connection
/// owns the activation name; no authentication/success method is registered.
pub fn claim_name(interface: super::touchbar::TouchBar) -> io::Result<zbus::Connection> {
    let owner = keychain_sep_driver::peer::effective_uid();
    let runtime = runtime(owner)?;
    let address = bus_address(&runtime, owner)?;
    bounded(
        async {
            let bus = zbus::connection::Builder::address(address.as_str())
                .map_err(failed)?
                .serve_at(super::touchbar::PATH, interface)
                .map_err(failed)?
                .build()
                .await
                .map_err(failed)?;
            bus.request_name_with_flags(
                AGENT_BUS_NAME,
                zbus::fdo::RequestNameFlags::DoNotQueue.into(),
            )
            .await
            .map_err(failed)?;
            Ok(bus)
        },
        &AtomicBool::new(false),
        START_TIMEOUT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    #[test]
    fn activation_timeout_and_cancellation_drop_pending_work() {
        let dropped = Arc::new(AtomicBool::new(false));
        let query = async {
            let _drop = Dropped(dropped.clone());
            std::future::pending::<io::Result<()>>().await
        };
        let start = Instant::now();
        assert_eq!(
            bounded(query, &AtomicBool::new(false), Duration::from_millis(10))
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(dropped.load(Ordering::Acquire));
        let active_cancel = AtomicBool::new(false);
        dropped.store(false, Ordering::Release);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(10));
                active_cancel.store(true, Ordering::Release);
            });
            let query = async {
                let _drop = Dropped(dropped.clone());
                std::future::pending::<io::Result<()>>().await
            };
            assert_eq!(
                bounded(query, &active_cancel, START_TIMEOUT)
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::Interrupted)
            );
        });
        assert!(dropped.load(Ordering::Acquire));
        let canceled = AtomicBool::new(true);
        assert_eq!(
            bounded(async { Ok(()) }, &canceled, START_TIMEOUT)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::Interrupted)
        );
    }
    #[test]
    fn full_agent_socket_backlog_cannot_block_activation_deadline() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("full.sock");
        let listener = socket2::Socket::from(std::os::unix::net::UnixListener::bind(&path)?);
        listener.listen(1)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let mut queued = Vec::new();
        let canceled = AtomicBool::new(false);
        let mut full = false;
        for _ in 0..8 {
            let connection = bounded(
                async { async_io::Async::<UnixStream>::connect(&path).await },
                &canceled,
                Duration::from_millis(10),
            );
            match connection {
                Ok(connection) => queued.push(connection),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::NotConnected
                            | io::ErrorKind::WouldBlock
                    ) =>
                {
                    full = true;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        assert!(full, "test did not fill the disposable socket backlog");
        assert!(
            queued.len() >= 2,
            "test did not establish initial queued connections"
        );
        let start = Instant::now();
        let result = bounded(
            async {
                socket_ready(&path, keychain_sep_driver::peer::effective_uid())
                    .await
                    .map(|_| ())
            },
            &canceled,
            Duration::from_millis(10),
        );
        assert!(matches!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut | io::ErrorKind::NotConnected | io::ErrorKind::WouldBlock)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        Ok(())
    }
    #[test]
    fn socket_probe_rejects_symlinks_wrong_owners_and_unprotected_sockets() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("agent.sock");
        let owner = keychain_sep_driver::peer::effective_uid();
        assert!(!async_io::block_on(socket_ready(&path, owner))?);
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(async_io::block_on(socket_ready(&path, owner))?);
        assert!(async_io::block_on(socket_ready(&path, owner + 1)).is_err());
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(async_io::block_on(socket_ready(&link, owner)).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
        assert!(async_io::block_on(socket_ready(&path, owner)).is_err());
        drop(listener);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(!async_io::block_on(socket_ready(&path, owner))?);
        Ok(())
    }
}
