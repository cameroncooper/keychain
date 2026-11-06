//! Privileged selected-credential operations. Transport peers supply UID; request
//! fields never override key ownership, session policy or stored provenance.
mod native;
mod protected;
mod registration;
pub mod registry;
pub mod session;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::prompt::{Presentation, PromptSession};
use crate::security::authorization::AuthorizationRequirement;
use crate::security::sep::{NativeSepProvider, sign_native};
use crate::{Error, Result};
use registry::Registry;
use session::ActiveSession;

const MAX_FRAME: usize = 512 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub id: Uuid,
    pub operation: Operation,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Operation {
    Status,
    Capabilities,
    Inspect {
        request_details_json: String,
    },
    ListCredentials,
    InspectCreation {
        request_details_json: String,
    },
    Create {
        transaction: Uuid,
        storage: crate::model::PasskeyProvenance,
        request_details_json: String,
    },
    ItemRecipient,
    ProtectionState {
        record: String,
    },
    RefreshProtectedMetadata {
        credential: Box<crate::model::PasskeyCredential>,
        public_sec1: String,
        revision: u64,
    },
    SetSyncedInventory {
        records: Vec<String>,
    },
    ImportProtected {
        import: Box<registry::ProtectedImport>,
    },
    VerifyProtected {
        record: String,
    },
    InspectProtected {
        record: String,
    },
    DiscardStaged {
        record: String,
        revision: u64,
    },
    AssertProtected {
        record: String,
        request_details_json: String,
    },
    DiagnosticSign {
        record: String,
        message: String,
    },
    DiagnosticCancelTest {
        record: String,
    },
    Assert {
        record: String,
        request_details_json: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub id: Uuid,
    pub result: Option<serde_json::Value>,
    pub error: Option<Failure>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub code: FailureCode,
    pub message: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FailureCode {
    Canceled,
    Expired,
    Busy,
    Unsupported,
    Refused,
    CredentialExcluded,
    InvalidRequest,
    Internal,
}
fn failure(error: Error) -> Failure {
    use crate::security::sep::ProviderError;
    let code = match &error {
        Error::CredentialExcluded => FailureCode::CredentialExcluded,
        Error::Sep(ProviderError::Canceled) => FailureCode::Canceled,
        Error::Sep(ProviderError::Expired) => FailureCode::Expired,
        Error::Sep(ProviderError::Busy) => FailureCode::Busy,
        Error::Sep(ProviderError::UnsupportedPolicy) => FailureCode::Unsupported,
        Error::Refused(_)
        | Error::Sep(ProviderError::Mismatch | ProviderError::PermissionDenied) => {
            FailureCode::Refused
        }
        Error::InvalidData(_) | Error::Json(_) => FailureCode::InvalidRequest,
        _ => FailureCode::Internal,
    };
    Failure {
        code,
        message: error.to_string(),
    }
}

pub fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> io::Result<T> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(io::Error::other("invalid broker message length"));
    }
    let mut data = vec![0; size];
    stream.read_exact(&mut data)?;
    serde_json::from_slice(&data).map_err(io::Error::other)
}
pub fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> io::Result<()> {
    let data = serde_json::to_vec(value).map_err(io::Error::other)?;
    if data.is_empty() || data.len() > MAX_FRAME {
        return Err(io::Error::other("broker response too large"));
    }
    stream.write_all(&(data.len() as u32).to_le_bytes())?;
    stream.write_all(&data)
}

pub fn call(socket: &Path, operation: Operation) -> Result<serde_json::Value> {
    call_cancelable(socket, operation, Arc::new(AtomicBool::new(false)))
}

pub fn call_cancelable(
    socket: &Path,
    operation: Operation,
    canceled: Arc<AtomicBool>,
) -> Result<serde_json::Value> {
    if canceled.load(Ordering::Acquire) {
        return Err(Error::Sep(crate::security::sep::ProviderError::Canceled));
    }
    let mut stream = UnixStream::connect(socket).map_err(|e| Error::io(socket, e))?;
    if keychain_sep_driver::peer::credentials(&stream)
        .map_err(|e| Error::io(socket, e))?
        .uid
        != 0
    {
        return Err(Error::Security("broker peer is not root".into()));
    }
    let _watch = CallWatch::new(&stream, canceled.clone()).map_err(|e| Error::io(socket, e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(125)))
        .map_err(|e| Error::io(socket, e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Error::io(socket, e))?;
    let id = Uuid::new_v4();
    write_frame(
        &mut stream,
        &Request {
            version: 1,
            id,
            operation,
        },
    )
    .map_err(|e| Error::io(socket, e))?;
    let reply = read_frame::<Response>(&mut stream);
    if canceled.load(Ordering::Acquire) {
        return Err(Error::Sep(crate::security::sep::ProviderError::Canceled));
    }
    let reply = reply.map_err(|e| Error::io(socket, e))?;
    if reply.version != 1 || reply.id != id || reply.result.is_some() == reply.error.is_some() {
        return Err(Error::Security("invalid broker response identity".into()));
    }
    reply.result.ok_or_else(|| {
        let Some(error) = reply.error else {
            return Error::InvalidData("missing broker outcome".into());
        };
        match error.code {
            FailureCode::Canceled => Error::Sep(crate::security::sep::ProviderError::Canceled),
            FailureCode::Expired => Error::Sep(crate::security::sep::ProviderError::Expired),
            FailureCode::Unsupported => {
                Error::Sep(crate::security::sep::ProviderError::UnsupportedPolicy)
            }
            FailureCode::CredentialExcluded => Error::CredentialExcluded,
            _ => Error::Refused(error.message),
        }
    })
}

struct CallWatch {
    done: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl CallWatch {
    fn new(stream: &UnixStream, canceled: Arc<AtomicBool>) -> io::Result<Self> {
        let socket = stream.try_clone()?;
        let done = Arc::new(AtomicBool::new(false));
        let finished = done.clone();
        let worker = std::thread::spawn(move || {
            while !finished.load(Ordering::Acquire) {
                if canceled.load(Ordering::Acquire) {
                    let _ = socket.shutdown(Shutdown::Both);
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        Ok(Self {
            done,
            worker: Some(worker),
        })
    }
}
impl Drop for CallWatch {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub struct Broker {
    pub registry: Registry,
    pub owner: u32,
    pub device: PathBuf,
    pub allow_diagnostics: bool,
    pub allow_item_decrypt: bool,
    active: Mutex<()>,
    seen: Mutex<std::collections::HashMap<Uuid, Instant>>,
}
impl Broker {
    pub fn new(registry: Registry, owner: u32, device: PathBuf, allow_diagnostics: bool) -> Self {
        Self {
            registry,
            owner,
            device,
            allow_diagnostics,
            allow_item_decrypt: false,
            active: Mutex::new(()),
            seen: Mutex::new(std::collections::HashMap::new()),
        }
    }
    pub fn handle(&self, stream: &mut UnixStream) -> Result<()> {
        let peer = keychain_sep_driver::peer::credentials(stream)
            .map_err(|e| Error::io("broker peer", e))?;
        if peer.uid != self.owner {
            return Err(Error::Refused(
                "caller is not the configured SEP identity owner".into(),
            ));
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| Error::io("broker request", e))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| Error::io("broker response", e))?;
        let request: Request = read_frame(stream).map_err(|e| Error::io("broker request", e))?;
        if request.version != 1 || request.id.is_nil() {
            return Err(Error::InvalidData("unsupported broker request".into()));
        }
        {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| Error::Security("request cache failed".into()))?;
            seen.retain(|_, at| at.elapsed() < Duration::from_secs(300));
            if seen.contains_key(&request.id) {
                return Err(Error::Refused("request ID was already used".into()));
            }
            if seen.len() >= 4096 {
                return Err(Error::Refused("request budget exhausted".into()));
            }
            seen.insert(request.id, Instant::now());
        }
        stream
            .set_read_timeout(None)
            .map_err(|e| Error::io("broker request", e))?;
        let watch = ClientWatch::new(stream).map_err(|e| Error::io("broker request", e))?;
        let result = self.execute(request.id, request.operation, watch.canceled.clone());
        if watch.canceled.load(Ordering::Acquire) {
            return Err(Error::Refused("caller disconnected or canceled".into()));
        }
        let reply = match result {
            Ok(value) => Response {
                version: 1,
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(error) => Response {
                version: 1,
                id: request.id,
                result: None,
                error: Some(failure(error)),
            },
        };
        write_frame(stream, &reply).map_err(|e| Error::io("broker response", e))
    }
    fn execute(
        &self,
        id: Uuid,
        operation: Operation,
        canceled: Arc<AtomicBool>,
    ) -> Result<serde_json::Value> {
        let session = ActiveSession::for_owner(self.owner)?;
        if matches!(operation, Operation::Status) {
            return Ok(
                serde_json::json!({"activeLocalSession": true, "owner": self.owner,
                "sepDevice":self.device_status()}),
            );
        }
        let _active = self
            .active
            .try_lock()
            .map_err(|_| Error::Refused("another key operation is active".into()))?;
        if matches!(operation, Operation::Capabilities) {
            return Ok(
                serde_json::json!({"userVerificationAvailable":self.verification_available()?}),
            );
        }
        let operation = match operation {
            Operation::ListCredentials => {
                return Ok(serde_json::to_value(
                    self.registry.browser_credentials(self.owner)?,
                )?);
            }
            Operation::InspectCreation { .. } | Operation::Create { .. } => {
                return self.execute_registration(id, operation, canceled, session);
            }
            Operation::Assert {
                record,
                request_details_json,
            } => {
                let credential = self
                    .registry
                    .browser_credentials(self.owner)?
                    .into_iter()
                    .find(|c| c.id == record)
                    .ok_or_else(|| {
                        Error::Refused("credential is not registered and verified".into())
                    })?;
                if credential.signing_key.backend_id == "sep-protected-software-v1" {
                    return self.execute_protected(
                        id,
                        Operation::AssertProtected {
                            record,
                            request_details_json,
                        },
                        canceled,
                        session,
                    );
                }
                Operation::Assert {
                    record,
                    request_details_json,
                }
            }
            Operation::Inspect {
                request_details_json,
            } => {
                let context = crate::browser::RequestContext::parse(&request_details_json)?;
                let vault = crate::model::VaultState {
                    schema_version: 1,
                    synced_at: 0,
                    credentials: vec![],
                    passkeys: self.registry.browser_credentials(self.owner)?,
                };
                let candidates = context.candidates(&vault)?;
                if candidates.is_empty() {
                    return Err(Error::Refused(
                        "no protected passkey matches this request".into(),
                    ));
                }
                return Ok(crate::browser::broker_inspection(&context, &candidates));
            }
            Operation::ItemRecipient
            | Operation::ProtectionState { .. }
            | Operation::RefreshProtectedMetadata { .. }
            | Operation::SetSyncedInventory { .. }
            | Operation::ImportProtected { .. }
            | Operation::VerifyProtected { .. }
            | Operation::InspectProtected { .. }
            | Operation::DiscardStaged { .. }
            | Operation::AssertProtected { .. } => {
                return self.execute_protected(id, operation, canceled, session);
            }
            other => other,
        };
        let cancellation_test = matches!(operation, Operation::DiagnosticCancelTest { .. });
        let (record_id, diagnostic_message, browser_details) = match operation {
            Operation::DiagnosticCancelTest { record } if self.allow_diagnostics => {
                (record, Some("keychain cancellation test v1".into()), None)
            }
            Operation::DiagnosticSign { record, message }
                if self.allow_diagnostics && !message.is_empty() && message.len() <= 1024 =>
            {
                (record, Some(message), None)
            }
            Operation::Assert {
                record,
                request_details_json,
            } => (record, None, Some(request_details_json)),
            _ => return Err(Error::Refused("operation is not enabled".into())),
        };
        let record = self.registry.load(&record_id, self.owner)?;
        let context = if let Some(details) = &browser_details {
            if record.diagnostic || !record.registered {
                return Err(Error::Refused("credential is not registered".into()));
            }
            let context = crate::browser::RequestContext::parse(details)?;
            let vault = crate::model::VaultState {
                schema_version: 1,
                synced_at: 0,
                credentials: vec![],
                passkeys: vec![record.credential.clone()],
            };
            if context.candidates(&vault)?.is_empty() {
                return Err(Error::Refused(
                    "credential is not eligible for this request".into(),
                ));
            }
            Some(context)
        } else {
            if !record.diagnostic {
                return Err(Error::Refused(
                    "diagnostic endpoint cannot use real credentials".into(),
                ));
            }
            None
        };
        let action = if cancellation_test {
            "Test cancellation — do not touch the reader".into()
        } else {
            context
                .as_ref()
                .map(|c| format!("Use your passkey for {}", c.rp_id))
                .unwrap_or_else(|| "Sign a disposable test message".into())
        };
        let authorization = self.native_authorization(
            Presentation {
                id,
                application: "Keychain".into(),
                action,
                account: record.credential.username.clone(),
            },
            canceled,
            session,
            cancellation_test,
        )?;
        let provider = authorization.provider(record.native_key, self.device.clone())?;
        let result = if let Some(context) = context {
            let public = provider.public_sec1()?;
            let assertion = crate::passkey::assertion_for_origin_with(
                &record.credential,
                &context.challenge,
                &context.origin,
                AuthorizationRequirement::UserVerification,
                |key, message, _| {
                    sign_native(&provider, key, &public, message, Duration::from_secs(60))
                        .map_err(Error::Sep)
                },
            )?;
            serde_json::json!({"responseJson": serde_json::to_string(&assertion)?})
        } else {
            let message = diagnostic_message
                .ok_or_else(|| Error::InvalidData("missing diagnostic message".into()))?;
            let outcome = sign_native(
                &provider,
                provider.reference(),
                &provider.public_sec1()?,
                message.as_bytes(),
                Duration::from_secs(60),
            )
            .map_err(Error::Sep)?;
            let signature = outcome.into_signature(
                provider.reference(),
                message.as_bytes(),
                AuthorizationRequirement::UserVerification,
            )?;
            serde_json::json!({"signatureDer": hex::encode(signature), "verified": true})
        };
        authorization.check()?;
        if cancellation_test {
            return Err(Error::Refused(
                "cancellation test completed with a fingerprint; no signature delivered".into(),
            ));
        }
        Ok(result)
    }
}

impl Broker {
    fn device_status(&self) -> &'static str {
        match keychain_sep_driver::Device::open(&self.device) {
            Ok(_) => "available",
            Err(keychain_sep_driver::Error::Unsupported) => "unsupported",
            Err(keychain_sep_driver::Error::Io(error)) => match error.raw_os_error() {
                Some(libc::EBUSY) => "busy",
                Some(libc::EPERM | libc::EACCES) => "permission-denied",
                _ => "unavailable",
            },
            Err(_) => "unavailable",
        }
    }
    fn verification_available(&self) -> Result<bool> {
        // Native creation is available even before the first credential exists.
        self.native_creation_available()
    }
    fn native_creation_available(&self) -> Result<bool> {
        if !self.native_ui_available()? {
            return Ok(false);
        }
        let Ok(device) = keychain_sep_driver::Device::open(&self.device) else {
            return Ok(false);
        };
        Ok(device.info().sensor_present != 0 && device.info().enrolled > 0)
    }
    fn native_ui_available(&self) -> Result<bool> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        let path = PathBuf::from(format!("/run/user/{}/keychain-auth.sock", self.owner));
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            return Ok(false);
        };
        if !meta.file_type().is_socket()
            || meta.uid() != self.owner
            || meta.permissions().mode() & 0o077 != 0
        {
            return Ok(false);
        }
        let Ok(agent) = UnixStream::connect(&path) else {
            return Ok(false);
        };
        if keychain_sep_driver::peer::credentials(&agent)
            .map_err(|e| Error::io(&path, e))?
            .uid
            != self.owner
        {
            return Ok(false);
        }
        drop(agent); // Liveness probe only: never present a dialog or start capture.
        Ok(true)
    }
}

struct ClientWatch {
    socket: UnixStream,
    canceled: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl ClientWatch {
    fn new(stream: &UnixStream) -> io::Result<Self> {
        let socket = stream.try_clone()?;
        let mut input = stream.try_clone()?;
        let canceled = Arc::new(AtomicBool::new(false));
        let signal = canceled.clone();
        let worker = std::thread::spawn(move || {
            // One operation per connection: any subsequent input is cancellation,
            // as is EOF. No client message can extend an authorization lifetime.
            let mut byte = [0];
            let _ = input.read(&mut byte);
            signal.store(true, Ordering::Release);
        });
        Ok(Self {
            socket,
            canceled,
            worker: Some(worker),
        })
    }
}
impl Drop for ClientWatch {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_cancel_closes_the_broker_connection_before_any_reply() {
        let (server, mut client) = UnixStream::pair().unwrap_or_else(|e| panic!("pair: {e}"));
        let canceled = Arc::new(AtomicBool::new(false));
        let watch =
            CallWatch::new(&server, canceled.clone()).unwrap_or_else(|e| panic!("watch: {e}"));
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|e| panic!("timeout: {e}"));
        canceled.store(true, Ordering::Release);
        let mut byte = [0];
        assert_eq!(
            client
                .read(&mut byte)
                .unwrap_or_else(|e| panic!("read: {e}")),
            0
        );
        drop(watch);
    }
    #[test]
    fn caller_disconnect_and_cancel_byte_terminate_the_request() {
        for cancel_byte in [false, true] {
            let (server, mut client) = UnixStream::pair().unwrap_or_else(|e| panic!("pair: {e}"));
            let watch = ClientWatch::new(&server).unwrap_or_else(|e| panic!("watch: {e}"));
            if cancel_byte {
                client
                    .write_all(&[1])
                    .unwrap_or_else(|e| panic!("cancel: {e}"));
            } else {
                client
                    .shutdown(Shutdown::Both)
                    .unwrap_or_else(|e| panic!("disconnect: {e}"));
            }
            let until = Instant::now() + Duration::from_secs(1);
            while !watch.canceled.load(Ordering::Acquire) && Instant::now() < until {
                std::thread::yield_now();
            }
            assert!(watch.canceled.load(Ordering::Acquire));
        }
    }
    #[test]
    fn oversized_messages_and_unknown_operations_fail_closed() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap_or_else(|e| panic!("pair: {e}"));
        sender
            .write_all(&((MAX_FRAME + 1) as u32).to_le_bytes())
            .unwrap_or_else(|e| panic!("write: {e}"));
        assert!(read_frame::<Request>(&mut receiver).is_err());
        assert!(
            serde_json::from_str::<Operation>(r#"{"kind":"decrypt","blob":"anything"}"#).is_err()
        );
    }
}
