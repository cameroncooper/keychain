//! Root-operation / unprivileged-session presentation protocol.
//! The agent can acknowledge display or cancel; it can never grant authorization.
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

pub mod activation;

const MAX_FRAME: usize = 8192;

/// Private broker/agent protocol. Upgrade both artifacts together; no v1 fallback.
pub const VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromptOperation {
    UsePasskey,
    CreatePasskey,
    VerifyPasskeyProtection,
    VerifyLoginProtection,
    RevealPassword,
    RevealNotes,
    GenerateCode,
    RevealLogin,
    DiagnosticSign,
    DiagnosticDecrypt,
    DiagnosticCancel,
}
impl PromptOperation {
    pub fn label(self) -> &'static str {
        match self {
            Self::UsePasskey => "Use a passkey",
            Self::CreatePasskey => "Create a passkey",
            Self::VerifyPasskeyProtection => "Verify passkey protection",
            Self::VerifyLoginProtection => "Verify login protection",
            Self::RevealPassword => "Reveal password",
            Self::RevealNotes => "Reveal notes",
            Self::GenerateCode => "Generate verification code",
            Self::RevealLogin => "Reveal password, notes and verification code",
            Self::DiagnosticSign => "Sign a disposable test message",
            Self::DiagnosticDecrypt => "Decrypt a disposable test item",
            Self::DiagnosticCancel => "Cancel without touching the fingerprint reader",
        }
    }
    pub fn heading(self) -> &'static str {
        if self == Self::DiagnosticCancel {
            "Cancellation check"
        } else {
            "Use your fingerprint"
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromptStorage {
    ICloudSynced,
    DeviceOnly,
    ProtectedLocalCopy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PromptTarget {
    WebAuthn {
        rp_id: String,
        origin: Option<String>,
    },
    Login {
        website: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    pub id: Uuid,
    pub operation: PromptOperation,
    pub account: String,
    pub target: Option<PromptTarget>,
    pub storage: Option<PromptStorage>,
}
impl Presentation {
    pub fn passkey(
        id: Uuid,
        operation: PromptOperation,
        rp_id: &str,
        origin: Option<&str>,
        account: &str,
        storage: crate::model::PasskeyProvenance,
    ) -> Self {
        Self {
            id,
            operation,
            account: account.into(),
            target: Some(PromptTarget::WebAuthn {
                rp_id: rp_id.into(),
                origin: origin.map(str::to_owned),
            }),
            storage: Some(match storage {
                crate::model::PasskeyProvenance::Synced => PromptStorage::ICloudSynced,
                crate::model::PasskeyProvenance::DeviceBound => PromptStorage::DeviceOnly,
            }),
        }
    }
    pub fn login(id: Uuid, operation: PromptOperation, website: &str, account: &str) -> Self {
        Self {
            id,
            operation,
            account: account.into(),
            target: Some(PromptTarget::Login {
                website: website.into(),
            }),
            storage: Some(PromptStorage::ProtectedLocalCopy),
        }
    }
    pub fn diagnostic(id: Uuid, operation: PromptOperation, account: &str) -> Self {
        Self {
            id,
            operation,
            account: account.into(),
            target: None,
            storage: None,
        }
    }
    pub fn storage_label(&self) -> Option<&'static str> {
        match (self.operation, self.storage?) {
            (PromptOperation::CreatePasskey, PromptStorage::ICloudSynced) => Some("Save in iCloud"),
            (PromptOperation::CreatePasskey, PromptStorage::DeviceOnly) => {
                Some("Save on this device only")
            }
            (_, PromptStorage::ICloudSynced) => Some("iCloud-synced"),
            (_, PromptStorage::DeviceOnly) => Some("This device only"),
            (_, PromptStorage::ProtectedLocalCopy) => Some("Protected local copy"),
        }
    }
    pub fn summary(&self) -> String {
        let label = self.operation.label();
        match &self.target {
            Some(PromptTarget::WebAuthn { rp_id, .. }) => format!("{label} for {rp_id}"),
            Some(PromptTarget::Login { website }) if !website.is_empty() => {
                format!("{label} for {website}")
            }
            _ => label.into(),
        }
    }
    pub fn requested_origin(&self) -> Option<&str> {
        match &self.target {
            Some(PromptTarget::WebAuthn { origin, .. }) => origin.as_deref(),
            _ => None,
        }
    }
    pub fn validate(&self) -> io::Result<()> {
        let invalid = || io::Error::other("invalid prompt presentation");
        let valid_text = |value: &str, maximum| {
            value.len() <= maximum && !value.chars().any(|c| c.is_control() || matches!(c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        };
        if self.id.is_nil() || !valid_text(&self.account, 512) {
            return Err(invalid());
        }
        use PromptOperation as O;
        match (&self.target, self.storage, self.operation) {
            (
                Some(PromptTarget::WebAuthn { rp_id, origin }),
                Some(PromptStorage::ICloudSynced | PromptStorage::DeviceOnly),
                O::UsePasskey | O::CreatePasskey | O::VerifyPasskeyProtection,
            ) => {
                if rp_id.is_empty()
                    || rp_id.len() > 253
                    || !rp_id.is_ascii()
                    || rp_id.ends_with('.')
                    || url::Host::parse(rp_id)
                        .map(|h| h.to_string())
                        .ok()
                        .as_deref()
                        != Some(rp_id)
                {
                    return Err(invalid());
                }
                match origin {
                    Some(origin)
                        if valid_text(origin, 2048)
                            && crate::passkey::validate_origin_for_rp(origin, rp_id)
                                .ok()
                                .as_deref()
                                == Some(origin) => {}
                    None if self.operation == O::VerifyPasskeyProtection => {}
                    _ => return Err(invalid()),
                }
            }
            (
                Some(PromptTarget::Login { website }),
                Some(PromptStorage::ProtectedLocalCopy),
                O::VerifyLoginProtection
                | O::RevealPassword
                | O::RevealNotes
                | O::GenerateCode
                | O::RevealLogin,
            ) if valid_text(website, 1024) => {}
            (None, None, O::DiagnosticSign | O::DiagnosticDecrypt | O::DiagnosticCancel) => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DisplayEvent {
    Present { version: u32, request: Presentation },
    Status { id: Uuid, message: String },
    Finished { id: Uuid },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AgentEvent {
    Visible { id: Uuid },
    Cancel { id: Uuid },
}

pub fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(io::Error::other("prompt message too large"));
    }
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)
}
pub fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> io::Result<T> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::other("invalid prompt frame size"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

/// Validate the complete private presentation before the agent opens a window.
pub fn read_presentation(stream: &mut UnixStream) -> io::Result<Presentation> {
    let DisplayEvent::Present {
        version: VERSION,
        request,
    } = read_frame(stream)?
    else {
        return Err(io::Error::other("unsupported prompt protocol or message"));
    };
    request.validate()?;
    Ok(request)
}

pub struct PromptSession {
    stream: UnixStream,
    id: Uuid,
    canceled: Arc<AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl PromptSession {
    /// The trusted caller supplies the owner derived from authenticated session
    /// state. Diagnostic callers may supply it explicitly; production clients may not.
    pub fn connect(path: &Path, owner: u32, request: Presentation) -> io::Result<Self> {
        if keychain_sep_driver::peer::effective_uid() != 0 {
            return Err(io::Error::other(
                "prompt caller must be the privileged operation service",
            ));
        }
        request.validate()?;
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_socket()
            || meta.uid() != owner
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::other(
                "prompt socket must be private and owned by the selected user",
            ));
        }
        let mut stream = UnixStream::connect(path)?;
        if keychain_sep_driver::peer::credentials(&stream)?.uid != owner {
            return Err(io::Error::other("wrong prompt-agent owner"));
        }
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        let id = request.id;
        write_frame(
            &mut stream,
            &DisplayEvent::Present {
                version: VERSION,
                request,
            },
        )?;
        match read_frame(&mut stream)? {
            AgentEvent::Visible { id: received } if received == id => (),
            _ => {
                let _ = stream.shutdown(Shutdown::Both);
                return Err(io::Error::other("prompt was not presented"));
            }
        }
        stream.set_read_timeout(None)?;
        let mut input = stream.try_clone()?;
        let canceled = Arc::new(AtomicBool::new(false));
        let signal = canceled.clone();
        let reader = std::thread::spawn(move || {
            // Any message, malformed input, or disconnect terminates permission
            // to continue. There is intentionally no agent-success variant.
            let _: io::Result<AgentEvent> = read_frame(&mut input);
            signal.store(true, Ordering::Release);
        });
        Ok(Self {
            stream,
            id,
            canceled,
            reader: Some(reader),
        })
    }
    pub fn canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }
    pub fn status(&mut self, message: &str) -> io::Result<()> {
        if message.len() > 512 || message.chars().any(char::is_control) {
            return Err(io::Error::other("invalid status"));
        }
        write_frame(
            &mut self.stream,
            &DisplayEvent::Status {
                id: self.id,
                message: message.into(),
            },
        )
    }
}
impl Drop for PromptSession {
    fn drop(&mut self) {
        let _ = write_frame(&mut self.stream, &DisplayEvent::Finished { id: self.id });
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_bounds_and_agent_success_are_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap_or_else(|e| panic!("pair: {e}"));
        a.write_all(&9000_u32.to_le_bytes())
            .unwrap_or_else(|e| panic!("write: {e}"));
        assert!(read_frame::<AgentEvent>(&mut b).is_err());
        assert!(
            serde_json::from_str::<AgentEvent>(
                r#"{"event":"success","id":"00000000-0000-0000-0000-000000000001"}"#
            )
            .is_err()
        );
    }
    fn assertion() -> Presentation {
        Presentation::passkey(
            Uuid::new_v4(),
            PromptOperation::UsePasskey,
            "example.com",
            Some("https://login.example.com:8443"),
            "alice",
            crate::model::PasskeyProvenance::Synced,
        )
    }
    #[test]
    fn fields_preserve_the_complete_origin_and_creation_does_not_claim_saved_state()
    -> io::Result<()> {
        let mut request = assertion();
        request.validate()?;
        assert_eq!(
            request.requested_origin(),
            Some("https://login.example.com:8443")
        );
        assert_eq!(request.storage_label(), Some("iCloud-synced"));
        let encoded = serde_json::to_vec(&request).map_err(io::Error::other)?;
        let decoded: Presentation = serde_json::from_slice(&encoded).map_err(io::Error::other)?;
        assert_eq!(request, decoded);
        request.operation = PromptOperation::CreatePasskey;
        request.validate()?;
        assert_eq!(request.storage_label(), Some("Save in iCloud"));
        request.storage = Some(PromptStorage::DeviceOnly);
        assert_eq!(request.storage_label(), Some("Save on this device only"));
        Ok(())
    }
    #[test]
    fn unbound_or_misleading_prompt_fields_are_refused() {
        let mut request = assertion();
        request.operation = PromptOperation::RevealPassword;
        assert!(request.validate().is_err());
        request = assertion();
        request.storage = Some(PromptStorage::ProtectedLocalCopy);
        assert!(request.validate().is_err());
        request = assertion();
        request.target = None;
        assert!(request.validate().is_err());
        request = assertion();
        request.id = Uuid::nil();
        assert!(request.validate().is_err());
        request = assertion();
        request.account = "alice\u{202e}evil".into();
        assert!(request.validate().is_err());
        request = assertion();
        request.account = "x".repeat(513);
        assert!(request.validate().is_err());
        request = assertion();
        request.operation = PromptOperation::DiagnosticSign;
        assert!(request.validate().is_err());
    }
    #[test]
    fn origin_and_rp_canonicalization_prevent_displaying_a_different_site() {
        for (rp, origin) in [
            ("example.com", "https://example.com.evil.invalid"),
            ("example.com", "https://example.com@evil.invalid"),
            ("example.com", "https://example.com/path"),
            ("example.com", "https://example.com?fake=1"),
            ("example.com", "http://example.com"),
            ("Example.com", "https://example.com"),
            ("example.com.", "https://example.com"),
            ("bücher.example", "https://xn--bcher-kva.example"),
        ] {
            let request = Presentation::passkey(
                Uuid::new_v4(),
                PromptOperation::UsePasskey,
                rp,
                Some(origin),
                "alice",
                crate::model::PasskeyProvenance::Synced,
            );
            assert!(request.validate().is_err(), "accepted {rp} / {origin}");
        }
        let request = Presentation::passkey(
            Uuid::new_v4(),
            PromptOperation::UsePasskey,
            "xn--bcher-kva.example",
            Some("https://xn--bcher-kva.example"),
            "alice",
            crate::model::PasskeyProvenance::Synced,
        );
        assert!(request.validate().is_ok());
        let mut request = assertion();
        if let Some(PromptTarget::WebAuthn { origin, .. }) = &mut request.target {
            *origin = None;
        }
        assert!(request.validate().is_err());
        request.operation = PromptOperation::VerifyPasskeyProtection;
        assert!(request.validate().is_ok());
        request.operation = PromptOperation::CreatePasskey;
        assert!(request.validate().is_err());
    }
    #[test]
    fn logins_and_diagnostics_do_not_claim_unproven_cloud_or_requester_identity() -> io::Result<()>
    {
        let mut login = Presentation::login(
            Uuid::new_v4(),
            PromptOperation::RevealPassword,
            "Example login",
            "alice",
        );
        login.validate()?;
        assert_eq!(login.storage_label(), Some("Protected local copy"));
        assert!(login.requested_origin().is_none());
        login.storage = Some(PromptStorage::ICloudSynced);
        assert!(login.validate().is_err());
        let diagnostic = Presentation::diagnostic(
            Uuid::new_v4(),
            PromptOperation::DiagnosticCancel,
            "Disposable key",
        );
        diagnostic.validate()?;
        assert_eq!(diagnostic.operation.heading(), "Cancellation check");
        let mut json = serde_json::to_value(diagnostic).map_err(io::Error::other)?;
        json["application"] = "Verified browser".into();
        assert!(serde_json::from_value::<Presentation>(json).is_err());
        Ok(())
    }
    #[test]
    fn agent_rejects_old_wire_versions_and_invalid_context_before_presentation() -> io::Result<()> {
        for version in [1, VERSION + 1] {
            let (mut sender, mut receiver) = UnixStream::pair()?;
            write_frame(
                &mut sender,
                &DisplayEvent::Present {
                    version,
                    request: assertion(),
                },
            )?;
            assert!(read_presentation(&mut receiver).is_err());
        }
        let (mut sender, mut receiver) = UnixStream::pair()?;
        let mut request = assertion();
        request.operation = PromptOperation::DiagnosticSign;
        write_frame(
            &mut sender,
            &DisplayEvent::Present {
                version: VERSION,
                request,
            },
        )?;
        assert!(read_presentation(&mut receiver).is_err());
        let request = assertion();
        write_frame(
            &mut sender,
            &DisplayEvent::Present {
                version: VERSION,
                request: request.clone(),
            },
        )?;
        assert_eq!(read_presentation(&mut receiver)?, request);
        Ok(())
    }
    #[test]
    fn peer_identity_comes_from_kernel() {
        let (a, _) = UnixStream::pair().unwrap_or_else(|e| panic!("pair: {e}"));
        let peer =
            keychain_sep_driver::peer::credentials(&a).unwrap_or_else(|e| panic!("peer: {e}"));
        assert_eq!(peer.uid, keychain_sep_driver::peer::effective_uid());
        assert_eq!(peer.pid as u32, std::process::id());
    }
}
