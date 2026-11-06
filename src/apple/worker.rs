//! Authenticated broker-to-network-worker transport. No passkey scalar, plaintext TLK,
//! account token, or verified-upload receipt is part of this wire protocol.
//! Deployment must give the worker a separate service UID and trusted account
//! credentials; owner/browser sockets are never interchangeable with this one.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::{fs::MetadataExt, net::UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::apple::ckks::upload::{Binding, SaveOutcome, Snapshot, UploadIo};
use crate::apple::ckks::{Record, ZoneIdentity};
use crate::apple::cloudkit::{DeviceConfig, atomic::AppleUploadIo, atomic::AtomicSave};
use crate::apple::pipeline::RecoveredTlk;
use crate::{Error, Result};

const MAX_HEADER: usize = 16 * 1024;
const MAX_PAYLOAD: usize = 64 * 1024 * 1024;
const IO_TICK: Duration = Duration::from_millis(40);

pub mod service;

/// Static account selection supplied by trusted service credentials. Per-call
/// transaction/browser bindings arrive only from the authenticated root broker.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountScope {
    pub owner: u32,
    pub account_fingerprint: String,
    pub peer_id: String,
    pub zone: ZoneIdentity,
}
impl AccountScope {
    fn accepts(&self, binding: &Binding) -> bool {
        self.owner == binding.owner
            && self.account_fingerprint == binding.account_fingerprint
            && self.peer_id == binding.peer_id
            && self.zone == binding.zone
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Kind {
    Hello,
    FetchPage,
    Save,
    Failed,
    AuthenticationRequired,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    binding: Binding,
    step: u64,
    kind: Kind,
    length: usize,
}

fn invalid(message: &str) -> Error {
    Error::Security(format!("Apple worker: {message}"))
}

/// Synchronous framing with cancellable partial reads AND writes. A partial
/// frame is never restarted. Any error permanently shuts down this connection.
struct Channel<'a> {
    stream: UnixStream,
    binding: Binding,
    deadline: Instant,
    check: &'a dyn Fn() -> Result<()>,
    healthy: bool,
}
impl<'a> Channel<'a> {
    fn new(
        stream: UnixStream,
        binding: Binding,
        deadline: Instant,
        check: &'a dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        binding.validate()?;
        stream
            .set_read_timeout(Some(IO_TICK))
            .map_err(|e| Error::io("worker timeout", e))?;
        stream
            .set_write_timeout(Some(IO_TICK))
            .map_err(|e| Error::io("worker timeout", e))?;
        let channel = Self {
            stream,
            binding,
            deadline,
            check,
            healthy: true,
        };
        channel.guard()?;
        Ok(channel)
    }
    fn guard(&self) -> Result<()> {
        if !self.healthy {
            return Err(invalid("channel is closed; reconcile before reconnecting"));
        }
        if Instant::now() >= self.deadline {
            return Err(crate::security::sep::ProviderError::Expired.into());
        }
        (self.check)()?;
        if Instant::now() >= self.deadline {
            return Err(crate::security::sep::ProviderError::Expired.into());
        }
        Ok(())
    }
    fn close(&mut self) {
        self.healthy = false;
        let _ = self.stream.shutdown(Shutdown::Both);
    }
    fn frames(&mut self) -> Frames<'_> {
        Frames {
            stream: &mut self.stream,
            binding: Some(&self.binding),
            deadline: self.deadline,
            check: self.check,
        }
    }
    fn read(&mut self, step: u64) -> Result<(Kind, Vec<u8>)> {
        self.guard()?;
        self.frames().read(step)
    }
    fn write(&mut self, step: u64, kind: Kind, body: &[u8]) -> Result<()> {
        self.guard()?;
        self.frames().write(step, kind, body)
    }
    #[cfg(test)]
    fn transfer(&mut self, bytes: &mut [u8], write: bool) -> Result<()> {
        self.guard()?;
        self.frames().transfer(bytes, write)
    }
}

/// Borrows both the socket and the CURRENT operation check. No guard outlives
/// the call, and no closure containing biometric authorization is persisted.
struct Frames<'a> {
    stream: &'a mut UnixStream,
    binding: Option<&'a Binding>,
    deadline: Instant,
    check: &'a dyn Fn() -> Result<()>,
}
impl Frames<'_> {
    fn guard(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(crate::security::sep::ProviderError::Expired.into());
        }
        (self.check)()?;
        if Instant::now() >= self.deadline {
            return Err(crate::security::sep::ProviderError::Expired.into());
        }
        Ok(())
    }
    fn transfer(&mut self, bytes: &mut [u8], write: bool) -> Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.guard()?;
            let result = if write {
                self.stream.write(&bytes[offset..])
            } else {
                self.stream.read(&mut bytes[offset..])
            };
            match result {
                Ok(0) => return Err(invalid("connection closed during frame")),
                Ok(count) => offset += count,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(Error::io("Apple worker frame", e)),
            }
        }
        self.guard()
    }
    fn write(&mut self, step: u64, kind: Kind, body: &[u8]) -> Result<()> {
        self.guard()?;
        if body.len() > MAX_PAYLOAD {
            return Err(invalid("payload exceeds limit"));
        }
        let mut bytes = serde_json::to_vec(&Header {
            version: 1,
            binding: self
                .binding
                .ok_or_else(|| invalid("unbound outgoing frame"))?
                .clone(),
            step,
            kind,
            length: body.len(),
        })?;
        if bytes.len() > MAX_HEADER {
            return Err(invalid("header exceeds limit"));
        }
        self.transfer(&mut (bytes.len() as u32).to_be_bytes(), true)?;
        self.transfer(&mut bytes, true)?;
        // Outbound payloads contain ciphertext/public protobuf metadata only.
        // Avoid cloning a potentially large payload just for mutable transfer.
        let mut offset = 0;
        while offset < body.len() {
            self.guard()?;
            match self.stream.write(&body[offset..]) {
                Ok(0) => return Err(invalid("connection closed during payload")),
                Ok(count) => offset += count,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(Error::io("Apple worker payload", e)),
            }
        }
        self.guard()
    }
    fn read(&mut self, step: u64) -> Result<(Kind, Vec<u8>)> {
        let (header, body) = self.envelope(step)?;
        Ok((header.kind, body))
    }
    fn envelope(&mut self, step: u64) -> Result<(Header, Vec<u8>)> {
        let mut size = [0u8; 4];
        self.transfer(&mut size, false)?;
        let size = u32::from_be_bytes(size) as usize;
        if size == 0 || size > MAX_HEADER {
            return Err(invalid("invalid header size"));
        }
        let mut bytes = vec![0; size];
        self.transfer(&mut bytes, false)?;
        let header: Header = serde_json::from_slice(&bytes)?;
        if header.version != 1
            || self
                .binding
                .is_some_and(|binding| &header.binding != binding)
            || header.step != step
            || header.length > MAX_PAYLOAD
        {
            return Err(invalid(
                "version, scope, sequence or payload bounds mismatch",
            ));
        }
        if self.binding.is_none() && (step != 0 || header.kind != Kind::Hello || header.length != 0)
        {
            return Err(invalid("only the initial empty handshake may select scope"));
        }
        if matches!(
            header.kind,
            Kind::Hello | Kind::Failed | Kind::AuthenticationRequired
        ) && header.length != 0
        {
            return Err(invalid("control frame contains payload"));
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(header.length)
            .map_err(|_| invalid("payload allocation failed"))?;
        payload.resize(header.length, 0);
        self.transfer(&mut payload, false)?;
        Ok((header, payload))
    }
}

impl Drop for Channel<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

/// A preconnected, kernel-authenticated service channel. Construct before any
/// biometric capture; there is no subprocess creation or reconnect in this API.
pub struct WorkerClient<'a> {
    channel: Channel<'a>,
    step: u64,
}
impl<'a> WorkerClient<'a> {
    /// This entry point is for the privileged broker. Configuration must come
    /// from its root-controlled service configuration, never an owner request.
    /// The worker UID must be dedicated and different from root and the owner.
    pub fn connect(
        socket: &Path,
        worker_uid: u32,
        binding: Binding,
        deadline: Instant,
        check: &'a dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        check()?;
        binding.validate()?;
        if Instant::now() >= deadline {
            return Err(crate::security::sep::ProviderError::Expired.into());
        }
        if keychain_sep_driver::peer::effective_uid() != 0 {
            return Err(invalid("only the privileged broker may connect"));
        }
        if !socket.is_absolute() {
            return Err(invalid("service socket must be absolute"));
        }
        for path in socket.ancestors() {
            let meta = std::fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
            if (meta.uid() != 0 && meta.uid() != worker_uid)
                || meta.mode() & 0o022 != 0
                || meta.file_type().is_symlink()
            {
                return Err(invalid(
                    "service socket path is writable by an untrusted identity",
                ));
            }
            if path == socket {
                use std::os::unix::fs::FileTypeExt;
                if !meta.file_type().is_socket() {
                    return Err(invalid("endpoint is not a socket"));
                }
            } else if !meta.is_dir() {
                return Err(invalid("socket ancestor is not a directory"));
            }
        }
        Self::authenticate(
            UnixStream::connect(socket).map_err(|e| Error::io(socket, e))?,
            worker_uid,
            binding,
            deadline,
            check,
        )
    }
    fn authenticate(
        stream: UnixStream,
        worker_uid: u32,
        binding: Binding,
        deadline: Instant,
        check: &'a dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        if worker_uid == 0
            || worker_uid == binding.owner
            || keychain_sep_driver::peer::credentials(&stream)
                .map_err(|e| Error::io("worker peer credentials", e))?
                .uid
                != worker_uid
        {
            return Err(invalid("peer is not the dedicated worker UID"));
        }
        let mut client = Self {
            channel: Channel::new(stream, binding, deadline, check)?,
            step: 0,
        };
        client.exchange(Kind::Hello, &[])?;
        Ok(client)
    }
    fn exchange(&mut self, kind: Kind, body: &[u8]) -> Result<Vec<u8>> {
        self.exchange_checked(kind, body, &|| Ok(()))
    }
    fn exchange_checked(
        &mut self,
        kind: Kind,
        body: &[u8],
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Vec<u8>> {
        let result = (|| {
            let step = self.step;
            self.step = step
                .checked_add(1)
                .ok_or_else(|| invalid("sequence exhausted"))?;
            self.channel.guard()?;
            let base_check = self.channel.check;
            let combined = || {
                base_check()?;
                check()
            };
            let mut frames = Frames {
                stream: &mut self.channel.stream,
                binding: Some(&self.channel.binding),
                deadline: self.channel.deadline,
                check: &combined,
            };
            frames.write(step, kind, body)?;
            let (reply, body) = frames.read(step)?;
            frames.guard()?;
            match reply {
                Kind::AuthenticationRequired => Err(Error::AuthenticationRequired("Apple worker requires fresh local authentication; reconcile any attempted write".into())),
                Kind::Failed => Err(Error::Apple("network worker failed; reconcile any attempted write before retrying".into())),
                reply if reply == kind => Ok(body),
                _ => Err(invalid("unexpected reply type")),
            }
        })();
        if result.is_err() {
            self.channel.close();
        }
        result
    }
}

/// Raw Apple transport only. Responses are still parsed/validated by the
/// broker. A backend cannot construct a VerifiedUpload or assert biometric UV.
pub trait NetworkBackend {
    fn binding(&self) -> &Binding;
    fn fetch_page(&mut self, request: &[u8]) -> Result<Vec<u8>>;
    fn save_stream(&mut self, request: &[u8]) -> Result<Vec<u8>>;
}
impl NetworkBackend for AppleUploadIo<'_, '_> {
    fn binding(&self) -> &Binding {
        self.worker_binding()
    }
    fn fetch_page(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        AppleUploadIo::fetch_page(self, request)
    }
    fn save_stream(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        self.send_prepared_save(request)
    }
}

/// Run in the separate service UID. The backend has already authenticated the
/// selected account and joined peer. An ordinary owner client is rejected by
/// the kernel credentials check before any frame or Apple request is read.
pub fn serve(
    stream: UnixStream,
    backend: &mut dyn NetworkBackend,
    deadline: Instant,
) -> Result<()> {
    authenticate_broker(&stream)?;
    let check = || Ok(());
    let mut channel = Channel::new(stream, backend.binding().clone(), deadline, &check)?;
    let (kind, _) = channel.read(0)?;
    if kind != Kind::Hello {
        return Err(invalid("missing initial handshake"));
    }
    channel.write(0, Kind::Hello, &[])?;
    serve_bound(&mut channel, backend)
}

fn authenticate_broker(stream: &UnixStream) -> Result<()> {
    if keychain_sep_driver::peer::effective_uid() == 0
        || keychain_sep_driver::peer::credentials(stream)
            .map_err(|e| Error::io("broker peer credentials", e))?
            .uid
            != 0
    {
        return Err(invalid(
            "worker requires a privileged broker peer and a separate service UID",
        ));
    }
    Ok(())
}

/// Accept a dynamic transaction only within the service's fixed account scope.
/// No backend (and hence no Apple request) is constructed for a wrong scope.
pub fn serve_account<B: NetworkBackend>(
    mut stream: UnixStream,
    scope: &AccountScope,
    backend: impl FnOnce(Binding) -> Result<B>,
    deadline: Instant,
) -> Result<()> {
    authenticate_broker(&stream)?;
    stream
        .set_read_timeout(Some(IO_TICK))
        .map_err(|e| Error::io("worker timeout", e))?;
    stream
        .set_write_timeout(Some(IO_TICK))
        .map_err(|e| Error::io("worker timeout", e))?;
    let check = || Ok(());
    let (header, _) = Frames {
        stream: &mut stream,
        binding: None,
        deadline,
        check: &check,
    }
    .envelope(0)?;
    header.binding.validate()?;
    if !scope.accepts(&header.binding) {
        return Err(invalid("broker selected another account/peer/owner/zone"));
    }
    let mut backend = backend(header.binding.clone())?;
    if backend.binding() != &header.binding {
        return Err(invalid("backend changed the authenticated scope"));
    }
    let mut channel = Channel::new(stream, header.binding, deadline, &check)?;
    channel.write(0, Kind::Hello, &[])?;
    serve_bound(&mut channel, &mut backend)
}

fn serve_bound(channel: &mut Channel<'_>, backend: &mut dyn NetworkBackend) -> Result<()> {
    for step in 1..=4096 {
        let (kind, request) = channel.read(step)?;
        let result = match kind {
            Kind::FetchPage if !request.is_empty() && request.len() <= 64 * 1024 => {
                backend.fetch_page(&request)
            }
            Kind::Save if !request.is_empty() && request.len() <= 2 * 1024 * 1024 => {
                backend.save_stream(&request)
            }
            _ => return Err(invalid("invalid worker operation")),
        };
        match result {
            Ok(body) => channel.write(step, kind, &body)?,
            Err(error) => {
                let kind = if matches!(error, Error::AuthenticationRequired(_)) {
                    Kind::AuthenticationRequired
                } else {
                    Kind::Failed
                };
                channel.write(step, kind, &[])?;
                return Err(error);
            }
        }
    }
    Err(invalid("operation count exceeded"))
}

/// UploadIo used inside the broker. Roots are supplied from its authenticated
/// Octagon-share pipeline; they are NEVER accepted from this worker protocol.
pub struct WorkerUploadIo<'a> {
    client: WorkerClient<'a>,
    device: DeviceConfig,
    roots: Vec<RecoveredTlk>,
}
impl<'a> WorkerUploadIo<'a> {
    pub fn new(
        client: WorkerClient<'a>,
        device: DeviceConfig,
        authenticated_roots: Vec<RecoveredTlk>,
    ) -> Result<Self> {
        if authenticated_roots.is_empty() || authenticated_roots.len() > 4096 {
            return Err(invalid("authenticated zone roots are required"));
        }
        Ok(Self {
            client,
            device,
            roots: authenticated_roots,
        })
    }
}
impl UploadIo for WorkerUploadIo<'_> {
    fn fetch_zone(
        &mut self,
        zone: &ZoneIdentity,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Snapshot> {
        if zone != &self.client.channel.binding.zone {
            return Err(invalid("fetch zone differs from fixed scope"));
        }
        let result = Snapshot::fetch_with(zone.clone(), self.roots.clone(), |body| {
            self.client.exchange_checked(Kind::FetchPage, body, check)
        })
        .and_then(|snapshot| {
            check()?;
            Ok(snapshot)
        });
        if result.is_err() {
            self.client.channel.close();
        }
        result
    }
    fn create_atomic(
        &mut self,
        attempt: Uuid,
        zone: &ZoneIdentity,
        record: &Record,
        pointer: &Record,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<SaveOutcome> {
        if zone != &self.client.channel.binding.zone
            || record.name != self.client.channel.binding.transaction.to_string()
        {
            return Err(invalid("save differs from fixed scope"));
        }
        let save = AtomicSave::new(&self.device, attempt, zone, record, pointer)?;
        let result = save
            .parse_response(
                &self
                    .client
                    .exchange_checked(Kind::Save, &save.body, check)?,
            )
            .and_then(|outcome| {
                check()?;
                Ok(outcome)
            });
        if result.is_err() {
            self.client.channel.close();
        }
        result
    }
}

#[cfg(test)]
mod tests;
