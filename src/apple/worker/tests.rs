use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;

#[test]
fn connect_backlog_is_bounded_and_checks_cancellation() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|e| Error::io("temporary socket", e))?;
    let path = directory.path().join("full.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&path).map_err(|e| Error::io(&path, e))?;
    let listener = socket2::Socket::from(listener);
    listener.listen(1).map_err(|e| Error::io(&path, e))?;
    let mut queued = Vec::new();
    let mut full = false;
    for _ in 0..8 {
        match connect_bounded(
            &path,
            Instant::now() + Duration::from_millis(30),
            &|| Ok(()),
        ) {
            Ok(connection) => queued.push(connection),
            Err(_) => {
                full = true;
                break;
            }
        }
    }
    assert!(full && queued.len() >= 2);
    let started = Instant::now();
    assert!(connect_bounded(&path, started + Duration::from_millis(80), &|| Ok(())).is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    let checks = std::cell::Cell::new(0);
    let canceled = || {
        checks.set(checks.get() + 1);
        Err(invalid("synthetic cancellation"))
    };
    let result = connect_bounded(&path, until(), &canceled);
    assert!(
        matches!(result, Err(Error::Security(message)) if message.contains("synthetic cancellation"))
    );
    assert!(checks.get() >= 1);
    Ok(())
}

fn binding() -> Binding {
    Binding {
        owner: keychain_sep_driver::peer::effective_uid().saturating_add(1),
        account_fingerprint: format!("SHA256:{}", STANDARD.encode([1; 32])),
        peer_id: format!("SHA256:{}", STANDARD.encode([2; 32])),
        transaction: Uuid::new_v4(),
        request_sha256: "ab".repeat(32),
        zone: ZoneIdentity {
            name: "Passwords".into(),
            owner: "synthetic-owner".into(),
        },
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
pub(crate) fn pair<'a>(
    binding: &Binding,
    check: &'a dyn Fn() -> Result<()>,
    deadline: Instant,
) -> Result<(WorkerClient<'a>, UnixStream)> {
    let (client, server) = UnixStream::pair().map_err(|e| Error::io("test pair", e))?;
    Ok((
        WorkerClient {
            channel: Channel::new(client, binding.clone(), deadline, check)?,
            step: 0,
        },
        server,
    ))
}
fn join(handle: thread::JoinHandle<Result<()>>) -> Result<()> {
    handle
        .join()
        .unwrap_or_else(|_| panic!("worker thread panic"))
}

/// Fake pre-authenticated channel ONLY in tests; peer UID enforcement is covered
/// separately by disposable service-process checks. Replies contain raw records.
pub(crate) fn root_read_fixture(
    socket: UnixStream,
    binding: Binding,
    recovery: Vec<u8>,
    page: Vec<u8>,
) -> thread::JoinHandle<Result<()>> {
    thread::spawn(move || {
        let check = || Ok(());
        let peer = binding.peer_id.clone();
        let mut channel = Channel::new(socket, binding, until(), &check)?;
        let (kind, request) = channel.read(0)?;
        assert_eq!(kind, Kind::RecoverableShares);
        assert_eq!(
            request,
            crate::apple::cuttlefish::encode_fetch_recoverable_tlkshares_request(&peer)
        );
        channel.write(0, kind, &recovery)?;
        let (kind, _) = channel.read(1)?;
        assert_eq!(kind, Kind::FetchPage);
        channel.write(1, kind, &page)
    })
}

#[test]
fn correlated_roundtrip_preserves_binary_payload_and_sequence() -> Result<()> {
    let scope = binding();
    let check = || Ok(());
    let (mut client, socket) = pair(&scope, &check, until())?;
    let server = thread::spawn(move || {
        let check = || Ok(());
        let mut channel = Channel::new(socket, scope, until(), &check)?;
        for step in 0..3 {
            let (kind, body) = channel.read(step)?;
            channel.write(step, kind, &body)?;
        }
        Ok(())
    });
    assert!(client.exchange(Kind::Hello, &[])?.is_empty());
    assert_eq!(client.exchange(Kind::FetchPage, &[0, 255, 1])?, [0, 255, 1]);
    let payload = vec![0xa5; 256 * 1024];
    assert_eq!(client.exchange(Kind::Save, &payload)?, payload);
    join(server)
}

#[test]
fn handshake_guard_is_not_retained_as_authorization_after_readiness() -> Result<()> {
    let scope = binding();
    let base = || Ok(());
    let (mut client, socket) = pair(&scope, &base, until())?;
    let server = thread::spawn(move || {
        let check = || Ok(());
        let mut channel = Channel::new(socket, scope, until(), &check)?;
        for step in 0..2 {
            let (kind, body) = channel.read(step)?;
            channel.write(step, kind, &body)?;
        }
        Ok(())
    });
    let live = std::cell::Cell::new(true);
    let preflight = || {
        if live.get() {
            Ok(())
        } else {
            Err(crate::security::sep::ProviderError::Expired.into())
        }
    };
    client.exchange_checked(Kind::Hello, &[], &preflight)?;
    live.set(false);
    // Post-handshake calls get a CURRENT check, never reuse a readiness grant.
    assert_eq!(
        client.exchange_checked(Kind::FetchPage, b"next", &|| Ok(()))?,
        b"next"
    );
    join(server)
}

#[test]
fn partial_frames_do_not_restart_after_read_timeouts() -> Result<()> {
    let scope = binding();
    let check = || Ok(());
    let (mut client, mut socket) = pair(&scope, &check, until())?;
    let server = thread::spawn(move || {
        // Read the request using normal framing, then deliberately split every
        // component of the response across an actual socket timeout.
        let check = || Ok(());
        let reader = socket.try_clone().map_err(|e| Error::io("clone", e))?;
        let mut channel = Channel::new(reader, scope.clone(), until(), &check)?;
        channel.read(0)?;
        let header = serde_json::to_vec(&Header {
            version: 1,
            binding: scope,
            step: 0,
            kind: Kind::FetchPage,
            length: 3,
        })?;
        let mut frame = (header.len() as u32).to_be_bytes().to_vec();
        frame.extend(header);
        frame.extend([1, 2, 3]);
        for part in [
            &frame[..2],
            &frame[2..6],
            &frame[6..frame.len() - 1],
            &frame[frame.len() - 1..],
        ] {
            socket
                .write_all(part)
                .map_err(|e| Error::io("fragment", e))?;
            thread::sleep(Duration::from_millis(65));
        }
        Ok(())
    });
    assert_eq!(client.exchange(Kind::FetchPage, b"request")?, [1, 2, 3]);
    join(server)
}

#[test]
fn wrong_scope_sequence_version_kind_and_control_payload_close_channel() -> Result<()> {
    for case in 0..9 {
        let scope = binding();
        let check = || Ok(());
        let (mut client, socket) = pair(&scope, &check, until())?;
        let server = thread::spawn(move || {
            let check = || Ok(());
            let mut channel = Channel::new(socket, scope.clone(), until(), &check)?;
            channel.read(0)?;
            let mut header = serde_json::to_value(Header {
                version: 1,
                binding: scope,
                step: 0,
                kind: Kind::FetchPage,
                length: 0,
            })?;
            match case {
                0 => header["binding"]["owner"] = serde_json::json!(77),
                1 => header["binding"]["transaction"] = serde_json::json!(Uuid::new_v4()),
                2 => header["binding"]["request_sha256"] = serde_json::json!("cd".repeat(32)),
                3 => header["step"] = serde_json::json!(1),
                4 => header["version"] = serde_json::json!(2),
                5 => header["kind"] = serde_json::json!("verified-upload"),
                6 => header["uploaded"] = serde_json::json!(true),
                7 => header["length"] = serde_json::json!(MAX_PAYLOAD + 1),
                _ => {
                    header["kind"] = serde_json::json!("hello");
                    header["length"] = serde_json::json!(1);
                }
            }
            let mut bytes = serde_json::to_vec(&header)?;
            channel.transfer(&mut (bytes.len() as u32).to_be_bytes(), true)?;
            channel.transfer(&mut bytes, true)
        });
        assert!(client.exchange(Kind::FetchPage, b"request").is_err());
        assert!(!client.channel.healthy);
        assert!(client.exchange(Kind::Save, b"must not send").is_err());
        join(server)?;
    }
    Ok(())
}

#[test]
fn oversized_header_is_rejected_before_body_and_disconnect_is_terminal() -> Result<()> {
    for bytes in [
        vec![],
        vec![0, 0],
        ((MAX_HEADER + 1) as u32).to_be_bytes().to_vec(),
    ] {
        let scope = binding();
        let check = || Ok(());
        let (mut client, mut socket) = pair(&scope, &check, until())?;
        let server = thread::spawn(move || {
            let check = || Ok(());
            let reader = socket.try_clone().map_err(|e| Error::io("clone", e))?;
            let mut channel = Channel::new(reader, scope, until(), &check)?;
            channel.read(0)?;
            socket
                .write_all(&bytes)
                .map_err(|e| Error::io("broken frame", e))?;
            Ok(())
        });
        assert!(client.exchange(Kind::FetchPage, b"request").is_err());
        assert!(!client.channel.healthy);
        join(server)?;
    }
    Ok(())
}

#[test]
fn cancellation_and_deadlines_interrupt_stalled_reads_and_writes() -> Result<()> {
    for writing in [false, true] {
        for cancel in [false, true] {
            let scope = binding();
            let canceled = Arc::new(AtomicBool::new(false));
            let flag = canceled.clone();
            let check = || {
                if canceled.load(Ordering::Acquire) {
                    Err(crate::security::sep::ProviderError::Canceled.into())
                } else {
                    Ok(())
                }
            };
            let (mut client, socket) = pair(
                &scope,
                &check,
                Instant::now() + Duration::from_millis(if cancel { 3000 } else { 120 }),
            )?;
            let blocker = thread::spawn(move || {
                thread::sleep(Duration::from_millis(120));
                flag.store(true, Ordering::Release);
                // Keep the peer alive long enough to distinguish cancellation
                // from a disconnect; never drain a blocked outgoing payload.
                thread::sleep(Duration::from_millis(300));
                drop(socket);
            });
            let start = Instant::now();
            let body = if writing {
                vec![1; 2 * 1024 * 1024]
            } else {
                vec![]
            };
            let result = client.exchange(Kind::Save, &body);
            assert!(result.is_err());
            assert!(start.elapsed() < Duration::from_millis(350));
            assert!(!client.channel.healthy);
            blocker.join().unwrap_or_else(|_| panic!("blocker thread"));
        }
    }
    Ok(())
}

#[test]
fn kernel_uid_authentication_cannot_be_replaced_by_scope_fields() -> Result<()> {
    let uid = keychain_sep_driver::peer::effective_uid();
    let check = || Ok(());
    for expected in [0, uid.saturating_add(1), uid.saturating_add(2)] {
        let (socket, _other) = UnixStream::pair().map_err(|e| Error::io("pair", e))?;
        assert!(
            WorkerClient::authenticate(socket, expected, binding(), until(), &check, &check)
                .is_err()
        );
    }
    let (socket, _other) = UnixStream::pair().map_err(|e| Error::io("pair", e))?;
    struct Never(Binding);
    impl NetworkBackend for Never {
        fn recoverable_shares(&mut self, _: &[u8]) -> Result<Vec<u8>> {
            panic!("untrusted client reached backend")
        }
        fn binding(&self) -> &Binding {
            &self.0
        }
        fn fetch_page(&mut self, _: &[u8]) -> Result<Vec<u8>> {
            panic!("untrusted client reached backend")
        }
        fn save_stream(&mut self, _: &[u8]) -> Result<Vec<u8>> {
            panic!("untrusted client reached backend")
        }
    }
    assert!(serve(socket, &mut Never(binding()), until()).is_err());
    Ok(())
}

#[test]
fn upload_adapter_reads_all_raw_pages_and_keeps_roots_off_the_wire() -> Result<()> {
    use crate::proto::{Writer, decode_fields, first_bytes};
    let scope = binding();
    let check = || Ok(());
    let zone = scope.zone.clone();
    let (client, socket) = pair(&scope, &check, until())?;
    let server = thread::spawn(move || {
        let check = || Ok(());
        let mut channel = Channel::new(socket, scope, until(), &check)?;
        for step in 0..2 {
            let (kind, body) = channel.read(step)?;
            assert_eq!(kind, Kind::FetchPage);
            let request = decode_fields(&body)?;
            let cursor = first_bytes(&request, 1);
            let response = if step == 0 {
                assert!(cursor.is_none());
                Writer::new().bytes(2, b"cursor").uint64(4, 1).finish()
            } else {
                assert_eq!(cursor, Some(b"cursor".as_slice()));
                Writer::new().uint64(4, 3).finish()
            };
            // This is the ordinary record-changes request: no TLK or key
            // representation is added for the worker.
            assert!(!body.windows(64).any(|bytes| bytes == [0xa5; 64]));
            channel.write(step, kind, &response)?;
        }
        Ok(())
    });
    let roots = vec![RecoveredTlk {
        uuid: Uuid::new_v4().to_string(),
        zone_name: zone.name.clone(),
        keyclass: "tlk".into(),
        key: zeroize::Zeroizing::new(vec![0xa5; 64]),
    }];
    let mut io = WorkerUploadIo::new(
        client,
        DeviceConfig {
            device_uuid: Uuid::new_v4().to_string(),
            serial: "synthetic".into(),
            name: "test".into(),
        },
        roots,
    )?;
    io.fetch_zone(&zone, &|| Ok(()))?;
    join(server)
}

#[test]
fn worker_failure_is_terminal_and_does_not_request_a_retry() -> Result<()> {
    for failure in [Kind::Failed, Kind::AuthenticationRequired] {
        let scope = binding();
        let check = || Ok(());
        let (mut client, socket) = pair(&scope, &check, until())?;
        let server = thread::spawn(move || {
            let check = || Ok(());
            let mut channel = Channel::new(socket, scope, until(), &check)?;
            let (kind, _) = channel.read(0)?;
            assert_eq!(kind, Kind::Save);
            channel.write(0, failure, &[])?;
            // A failure may hide an accepted write; client must close and
            // cannot resend or reuse this connection for reconciliation.
            assert!(channel.read(1).is_err());
            Ok(())
        });
        assert!(client.exchange(Kind::Save, b"ciphertext").is_err());
        assert!(client.exchange(Kind::Save, b"ciphertext").is_err());
        join(server)?;
    }
    Ok(())
}

#[test]
fn current_operation_check_interrupts_io_even_when_constructor_check_stays_valid() -> Result<()> {
    for reason in 0..3 {
        let scope = binding();
        let constructor = || Ok(());
        let (client, socket) = pair(&scope, &constructor, until())?;
        let changed = Arc::new(AtomicBool::new(false));
        let flag = changed.clone();
        let zone = scope.zone.clone();
        let server = thread::spawn(move || {
            let check = || Ok(());
            let mut channel = Channel::new(socket, scope, until(), &check)?;
            channel.read(0)?;
            flag.store(true, Ordering::Release);
            // Keep the response pending while the CURRENT guard changes. The
            // constructor-time guard deliberately remains valid throughout.
            assert!(channel.read(1).is_err());
            Ok(())
        });
        let mut io = WorkerUploadIo::new(
            client,
            DeviceConfig {
                device_uuid: Uuid::new_v4().to_string(),
                serial: "synthetic".into(),
                name: "test".into(),
            },
            vec![RecoveredTlk {
                uuid: Uuid::new_v4().to_string(),
                zone_name: zone.name.clone(),
                keyclass: "tlk".into(),
                key: zeroize::Zeroizing::new(vec![0xa5; 64]),
            }],
        )?;
        let check = || {
            if !changed.load(Ordering::Acquire) {
                return Ok(());
            }
            Err(match reason {
                0 => crate::security::sep::ProviderError::Canceled.into(),
                1 => crate::security::sep::ProviderError::Expired.into(),
                _ => Error::Refused("synthetic session is locked".into()),
            })
        };
        let start = Instant::now();
        assert!(io.fetch_zone(&zone, &check).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(!io.client.channel.healthy);
        join(server)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires root; runs a disposable unprivileged worker with no Apple/SEP access"]
fn root_dedicated_worker_handshake_and_raw_io() -> Result<()> {
    use std::os::unix::{
        fs::{PermissionsExt, chown},
        net::UnixListener,
        process::CommandExt,
    };
    const CHILD: &str = "KEYCHAIN_SYNTHETIC_WORKER_SOCKET";
    const SCOPE: &str = "KEYCHAIN_SYNTHETIC_WORKER_SCOPE";
    if let Some(socket) = std::env::var_os(CHILD) {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 65534);
        struct Echo {
            binding: Binding,
            calls: usize,
        }
        impl NetworkBackend for Echo {
            fn recoverable_shares(&mut self, _: &[u8]) -> Result<Vec<u8>> {
                panic!("not a recoverable-share fixture")
            }
            fn binding(&self) -> &Binding {
                &self.binding
            }
            fn fetch_page(&mut self, request: &[u8]) -> Result<Vec<u8>> {
                self.calls += 1;
                Ok(request.to_vec())
            }
            fn save_stream(&mut self, request: &[u8]) -> Result<Vec<u8>> {
                self.calls += 1;
                Ok(request.to_vec())
            }
        }
        let scope: Binding = serde_json::from_str(
            &std::env::var(SCOPE).map_err(|_| invalid("missing synthetic scope"))?,
        )?;
        let listener =
            UnixListener::bind(&socket).map_err(|e| Error::io("synthetic listener", e))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io("synthetic permissions", e))?;
        let (stream, _) = listener
            .accept()
            .map_err(|e| Error::io("synthetic accept", e))?;
        let mut backend = Echo {
            binding: scope,
            calls: 0,
        };
        // The owner disconnects after two requests. That is terminal, not a
        // reason for the worker to reconnect or repeat either operation.
        assert!(serve(stream, &mut backend, until()).is_err());
        assert_eq!(backend.calls, 2);
        return Ok(());
    }
    assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
    let temp = tempfile::Builder::new()
        .prefix("keychain-worker-check-")
        .tempdir_in("/run")
        .map_err(|e| Error::io("synthetic directory", e))?;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o711))
        .map_err(|e| Error::io(temp.path(), e))?;
    let directory = temp.path().join("worker");
    std::fs::create_dir(&directory).map_err(|e| Error::io(&directory, e))?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(&directory, e))?;
    chown(&directory, Some(65534), Some(65534)).map_err(|e| Error::io(&directory, e))?;
    // Do not grant the service UID access to the user's home/build directory.
    let binary = temp.path().join("test-worker");
    std::fs::copy(
        std::env::current_exe().map_err(|e| Error::io("test exe", e))?,
        &binary,
    )
    .map_err(|e| Error::io(&binary, e))?;
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| Error::io(&binary, e))?;
    let socket = directory.join("worker.sock");
    let mut scope = binding();
    scope.owner = 1001;
    let mut child = std::process::Command::new(&binary)
        .args([
            "--exact",
            "apple::worker::tests::root_dedicated_worker_handshake_and_raw_io",
            "--ignored",
            "--nocapture",
        ])
        .uid(65534)
        .gid(65534)
        .env(CHILD, &socket)
        .env(SCOPE, serde_json::to_string(&scope)?)
        .spawn()
        .map_err(|e| Error::io("synthetic child", e))?;
    let result = (|| {
        let deadline = until();
        while !socket.exists() {
            if child
                .try_wait()
                .map_err(|e| Error::io("worker status", e))?
                .is_some()
                || Instant::now() >= deadline
            {
                return Err(invalid("synthetic worker did not become ready"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        let check = || Ok(());
        let mut client = WorkerClient::connect(&socket, 65534, scope, deadline, &check, &check)?;
        assert_eq!(client.exchange(Kind::FetchPage, b"page")?, b"page");
        assert_eq!(client.exchange(Kind::Save, b"ciphertext")?, b"ciphertext");
        drop(client);
        // The worker has its own deadline; still bound parent-side cleanup.
        while child
            .try_wait()
            .map_err(|e| Error::io("worker status", e))?
            .is_none()
        {
            if Instant::now() >= deadline {
                return Err(invalid("synthetic worker did not exit"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            child
                .wait()
                .map_err(|e| Error::io("worker wait", e))?
                .success()
        );
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
