//! Fixed systemd worker startup and preflight socket connection. This module
//! uses AF_UNIX/D-Bus only; it never performs Apple HTTP or launches a child.
use super::*;
use crate::apple::ckks::upload::Binding;
use crate::apple::worker::WorkerClient;
use crate::broker::account::WorkerSettings;
use crate::security::sep::ProviderError;
use std::future::Future;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

const WORKER_UNIT: &str = "keychain-network-worker.service";

fn guard(deadline: Instant, check: &dyn Fn() -> Result<()>) -> Result<()> {
    check()?;
    if Instant::now() >= deadline {
        return Err(ProviderError::Expired.into());
    }
    Ok(())
}
fn wait<T>(
    future: impl Future<Output = zbus::Result<T>>,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<T> {
    guard(deadline, check)?;
    let value = async_io::block_on(futures_lite::future::or(
        async {
            future.await.map_err(|_| {
                Error::Refused("could not start the configured Apple network worker".into())
            })
        },
        async {
            loop {
                guard(deadline, check)?;
                async_io::Timer::after(Duration::from_millis(40)).await;
            }
        },
    ))?;
    guard(deadline, check)?;
    Ok(value)
}
fn start_unit(
    connection: &zbus::Connection,
    unit: &str,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
    // StartUnit is idempotent for an already running service. "fail" refuses
    // conflicting jobs instead of replacing a stop/rotation already in flight.
    let reply = wait(
        connection.call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "StartUnit",
            &(unit, "fail"),
        ),
        deadline,
        check,
    )?;
    let job: OwnedObjectPath = reply
        .body()
        .deserialize()
        .map_err(|_| Error::Security("invalid worker-start reply".into()))?;
    let reply = wait(
        connection.call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "GetUnit",
            &(unit,),
        ),
        deadline,
        check,
    )?;
    let path = reply
        .body()
        .deserialize()
        .map_err(|_| Error::Security("invalid worker unit path".into()))?;
    Ok((path, job))
}
fn unit_state(
    connection: &zbus::Connection,
    path: &OwnedObjectPath,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<String> {
    let reply = wait(
        connection.call_method(
            Some("org.freedesktop.systemd1"),
            path.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "GetAll",
            &("org.freedesktop.systemd1.Unit",),
        ),
        deadline,
        check,
    )?;
    let properties: std::collections::HashMap<String, OwnedValue> = reply
        .body()
        .deserialize()
        .map_err(|_| Error::Security("invalid worker state reply".into()))?;
    let state = properties
        .get("ActiveState")
        .and_then(|value| <&str>::try_from(value).ok())
        .ok_or_else(|| Error::Security("worker state missing".into()))?;
    if matches!(state, "failed" | "deactivating") {
        return Err(Error::Refused("Apple network worker is unavailable; finish its account setup before creating an iCloud passkey".into()));
    }
    Ok(state.into())
}

fn job_live(
    connection: &zbus::Connection,
    path: &OwnedObjectPath,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<bool> {
    let reply = wait(
        async {
            Ok(connection
                .call_method(
                    Some("org.freedesktop.systemd1"),
                    path.as_str(),
                    Some("org.freedesktop.DBus.Properties"),
                    "GetAll",
                    &("org.freedesktop.systemd1.Job",),
                )
                .await)
        },
        deadline,
        check,
    )?;
    match reply {
        Ok(reply) => {
            let properties: std::collections::HashMap<String, OwnedValue> = reply
                .body()
                .deserialize()
                .map_err(|_| Error::Security("invalid worker job reply".into()))?;
            let state = properties
                .get("State")
                .and_then(|value| <&str>::try_from(value).ok());
            Ok(matches!(state, Some("waiting" | "running")))
        }
        Err(zbus::Error::MethodError(name, _, _))
            if matches!(
                name.as_str(),
                "org.freedesktop.DBus.Error.UnknownObject" | "org.freedesktop.systemd1.NoSuchJob"
            ) =>
        {
            Ok(false)
        }
        Err(_) => Err(Error::Refused(
            "cannot determine network worker startup state".into(),
        )),
    }
}

pub(super) fn connect_worker<'a>(
    settings: &WorkerSettings,
    binding: Binding,
    preflight_deadline: Instant,
    channel_deadline: Instant,
    connection_check: &'a dyn Fn() -> Result<()>,
    preflight: &dyn Fn() -> Result<()>,
) -> Result<WorkerClient<'a>> {
    if keychain_sep_driver::peer::effective_uid() != 0 {
        return Err(Error::Refused(
            "worker startup requires the privileged broker".into(),
        ));
    }
    guard(preflight_deadline, preflight)?;
    if settings
        .socket
        .try_exists()
        .map_err(|e| Error::io(&settings.socket, e))?
    {
        match WorkerClient::connect(
            &settings.socket,
            settings.uid,
            binding.clone(),
            channel_deadline,
            connection_check,
            preflight,
        ) {
            Ok(client) => return Ok(client),
            Err(Error::Io { source, .. })
                if matches!(
                    source.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => return Err(error),
        }
    }
    // An administrator-enrolled custom socket may belong to a separately
    // managed isolated worker. The fixed production unit cannot create it.
    if settings.socket != Path::new("/run/keychain-network/worker.sock") {
        return Err(Error::Refused(
            "configured custom worker is unavailable; start its service explicitly".into(),
        ));
    }
    let connection = wait(zbus::Connection::system(), preflight_deadline, preflight)?;
    let (path, job) = start_unit(&connection, WORKER_UNIT, preflight_deadline, preflight)?;
    loop {
        guard(preflight_deadline, preflight)?;
        if unit_state(&connection, &path, preflight_deadline, preflight)? == "inactive"
            && !job_live(&connection, &job, preflight_deadline, preflight)?
        {
            return Err(Error::Refused(
                "Apple network worker exited before becoming ready".into(),
            ));
        }
        if settings
            .socket
            .try_exists()
            .map_err(|e| Error::io(&settings.socket, e))?
        {
            match WorkerClient::connect(
                &settings.socket,
                settings.uid,
                binding.clone(),
                channel_deadline,
                connection_check,
                preflight,
            ) {
                Ok(client) => return Ok(client),
                Err(Error::Io { source, .. })
                    if matches!(
                        source.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires root; temporary local socket only, no systemd, Apple or SEP IO"]
    fn root_custom_worker_authentication_fails_before_any_service_start() -> Result<()> {
        use std::io::Read;
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let temp = tempfile::Builder::new()
            .prefix("keychain-custom-worker-")
            .tempdir_in("/run")
            .map_err(|e| Error::io("test runtime directory", e))?;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(temp.path(), e))?;
        let path = temp.path().join("worker.sock");
        let settings = WorkerSettings {
            uid: 65534,
            socket: path.clone(),
        };
        let binding = Binding {
            owner: 1001,
            account_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            peer_id: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            zone: crate::apple::ckks::ZoneIdentity {
                name: "Passwords".into(),
                owner: "synthetic-owner".into(),
            },
            transaction: Uuid::new_v4(),
            request_sha256: "ab".repeat(32),
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        let absent = connect_worker(
            &settings,
            binding.clone(),
            deadline,
            deadline,
            &|| Ok(()),
            &|| Ok(()),
        );
        assert!(
            matches!(absent, Err(Error::Refused(message)) if message.contains("custom worker"))
        );
        let listener = UnixListener::bind(&path).map_err(|e| Error::io(&path, e))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io(&path, e))?;
        let server = std::thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener
                .accept()
                .map_err(|e| Error::io("test listener", e))?;
            let mut byte = [0];
            assert_eq!(
                stream
                    .read(&mut byte)
                    .map_err(|e| Error::io("test socket", e))?,
                0
            );
            Ok(())
        });
        let wrong_peer =
            connect_worker(&settings, binding, deadline, deadline, &|| Ok(()), &|| {
                Ok(())
            });
        assert!(
            matches!(wrong_peer, Err(Error::Security(message)) if message.contains("dedicated worker UID"))
        );
        server
            .join()
            .map_err(|_| Error::Security("fixture thread failed".into()))??;
        Ok(())
    }
    #[test]
    fn startup_wait_cancels_expires_and_discards_a_late_result() {
        let deadline = Instant::now() + Duration::from_secs(1);
        assert!(
            wait(
                std::future::pending::<zbus::Result<()>>(),
                deadline,
                &|| Err(ProviderError::Canceled.into())
            )
            .is_err()
        );
        assert!(
            wait(
                std::future::pending::<zbus::Result<()>>(),
                Instant::now() + Duration::from_millis(5),
                &|| Ok(())
            )
            .is_err()
        );
        let canceled = AtomicBool::new(false);
        let result = async {
            canceled.store(true, Ordering::Release);
            Ok(())
        };
        assert!(
            wait(result, deadline, &|| if canceled.load(Ordering::Acquire) {
                Err(ProviderError::Canceled.into())
            } else {
                Ok(())
            })
            .is_err()
        );
    }

    #[test]
    #[ignore = "requires root/systemd; disposable sleep service only, no Apple/SEP IO"]
    fn root_systemd_start_is_observable_and_does_not_restart_an_active_service() -> Result<()> {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        struct Unit {
            name: String,
            file: PathBuf,
        }
        impl Drop for Unit {
            fn drop(&mut self) {
                let _ = std::process::Command::new("/usr/bin/systemctl")
                    .args(["stop", &self.name])
                    .output();
                let _ = std::fs::remove_file(&self.file);
                let _ = std::process::Command::new("/usr/bin/systemctl")
                    .arg("daemon-reload")
                    .output();
            }
        }
        let name = format!("keychain-worker-start-check-{}.service", Uuid::new_v4());
        let file = PathBuf::from("/run/systemd/system").join(&name);
        let unit = Unit { name, file };
        crate::paths::create_private_exclusive(&unit.file, b"[Service]\nType=exec\nUser=65534\nGroup=65534\nExecStartPre=/usr/bin/sleep 0.2\nExecStart=/usr/bin/sleep 6\nTimeoutStopSec=1\n")?;
        let status = std::process::Command::new("/usr/bin/systemctl")
            .arg("daemon-reload")
            .status()
            .map_err(|e| Error::io("test unit reload", e))?;
        assert!(status.success());
        let active_session = std::env::var("KEYCHAIN_TEST_ACTIVE_SESSION_OWNER")
            .ok()
            .map(|value| {
                let owner = value
                    .parse()
                    .map_err(|_| Error::InvalidData("invalid test session owner".into()))?;
                ActiveSession::for_owner(owner)
            })
            .transpose()?;
        let check = || {
            if active_session
                .as_ref()
                .is_some_and(|session| !session.valid())
            {
                Err(ProviderError::Canceled.into())
            } else {
                Ok(())
            }
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let connection = wait(zbus::Connection::system(), deadline, &check)?;
        let (path, job) = start_unit(&connection, &unit.name, deadline, &check)?;
        while unit_state(&connection, &path, deadline, &check)? != "active" {
            // This is the exact startup job handle, not a presumed live process.
            let _ = job_live(&connection, &job, deadline, &check)?;
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid = || -> Result<u32> {
            let reply = wait(
                connection.call_method(
                    Some("org.freedesktop.systemd1"),
                    path.as_str(),
                    Some("org.freedesktop.DBus.Properties"),
                    "GetAll",
                    &("org.freedesktop.systemd1.Service",),
                ),
                deadline,
                &check,
            )?;
            let properties: std::collections::HashMap<String, OwnedValue> = reply
                .body()
                .deserialize()
                .map_err(|_| Error::Security("test service properties".into()))?;
            properties
                .get("MainPID")
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| Error::Security("test service PID missing".into()))
        };
        let first = pid()?;
        assert_ne!(first, 0);
        start_unit(&connection, &unit.name, deadline, &check)?;
        assert_eq!(pid()?, first);
        Ok(())
    }
}
