//! Selected login import and intentional reveal. Passkey scalars and TOTP seeds
//! have no reveal operation. Plaintext fields are borrowed from protected memory.
use super::*;
use crate::model::Credential;
use crate::security::sep::{ProviderError, envelope};
use keychain_sep_driver::memory::{LockedBuffer, SecretBuffer};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"KCLOGIN\x01";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LoginMetadata {
    pub id: String,
    pub domain: String,
    pub username: String,
    pub title: String,
    pub modified_at: f64,
    pub last_used: f64,
    pub has_password: bool,
    pub has_notes: bool,
    pub has_totp: bool,
}
impl From<&Credential> for LoginMetadata {
    fn from(item: &Credential) -> Self {
        Self {
            id: item.id.clone(),
            domain: item.domain.clone(),
            username: item.username.clone(),
            title: item.title.clone(),
            modified_at: item.modified_at,
            last_used: item.last_used,
            has_password: !item.password.is_empty(),
            has_notes: !item.notes.is_empty(),
            has_totp: !item.totp_uri.is_empty(),
        }
    }
}
impl LoginMetadata {
    pub fn from_credential(item: &Credential) -> Result<Self> {
        let metadata = Self::from(item);
        metadata.validate()?;
        Ok(metadata)
    }
    pub(super) fn validate(&self) -> Result<()> {
        crate::paths::validate_record_id(&self.id)?;
        if !self.modified_at.is_finite()
            || !self.last_used.is_finite()
            || [&self.domain, &self.username, &self.title]
                .iter()
                .any(|value| value.len() > 1024 || value.chars().any(char::is_control))
        {
            return Err(Error::InvalidData("invalid login metadata".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginImport {
    pub expected_revision: u64,
    pub recipient_id: String,
    pub metadata: LoginMetadata,
    pub content_binding: String,
    pub sealed: Vec<u8>,
}
impl LoginImport {
    /// Encrypt a selected source, retaining the original recovery copy. The
    /// request carries ciphertext and public metadata, never plaintext fields.
    pub fn seal(
        owner: u32,
        recipient: &registry::Recipient,
        expected_revision: u64,
        item: &Credential,
    ) -> Result<Self> {
        let metadata = LoginMetadata::from_credential(item)?;
        let revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| Error::InvalidData("login revision overflow".into()))?;
        let mut memory = SecretBuffer::new().map_err(|e| Error::io("login sealing memory", e))?;
        let mut length = 46usize;
        let fields = [&item.password, &item.notes, &item.totp_uri];
        for field in fields {
            length = length
                .checked_add(field.len())
                .filter(|length| *length <= 4096)
                .ok_or_else(|| Error::InvalidData("login exceeds item envelope limit".into()))?;
        }
        let bytes = &mut memory.as_mut_array()[..length];
        bytes[..8].copy_from_slice(MAGIC);
        rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut bytes[8..40])
            .map_err(|_| Error::Security("login content randomness unavailable".into()))?;
        let mut offset = 46;
        for (index, field) in fields.iter().enumerate() {
            bytes[40 + index * 2..42 + index * 2]
                .copy_from_slice(&(field.len() as u16).to_be_bytes());
            bytes[offset..offset + field.len()].copy_from_slice(field.as_bytes());
            offset += field.len();
        }
        let content_binding = content_binding(bytes)?;
        LoginView::parse(bytes, &metadata, &content_binding)?;
        let binding = login_binding(owner, revision, &recipient.id, &metadata, &content_binding)?;
        let sealed = envelope::seal_item(
            &registry::decode_public(&recipient.public_sec1)?,
            &binding,
            bytes,
        )?;
        Ok(Self {
            expected_revision,
            recipient_id: recipient.id.clone(),
            metadata,
            content_binding,
            sealed,
        })
    }
}

pub(super) fn login_binding(
    owner: u32,
    revision: u64,
    recipient: &str,
    metadata: &LoginMetadata,
    content_binding: &str,
) -> Result<Vec<u8>> {
    metadata.validate()?;
    crate::paths::validate_record_id(recipient)?;
    if owner == 0
        || revision == 0
        || content_binding.len() != 64
        || hex::decode(content_binding)
            .map(|bytes| hex::encode(bytes) != content_binding)
            .unwrap_or(true)
    {
        return Err(Error::InvalidData("invalid login owner/revision".into()));
    }
    #[derive(Serialize)]
    struct Binding<'a> {
        application: &'static str,
        version: u32,
        owner: u32,
        record: &'a str,
        revision: u64,
        recipient: &'a str,
        purpose: &'static str,
        algorithm: &'static str,
        metadata_sha256: String,
        content_binding: &'a str,
    }
    Ok(serde_json::to_vec(&Binding {
        application: "cameroncooper.keychain",
        version: 1,
        owner,
        record: &metadata.id,
        revision,
        recipient,
        purpose: "login-secret-fields",
        algorithm: "utf8-fields-v1",
        metadata_sha256: hex::encode(Sha256::digest(serde_json::to_vec(metadata)?)),
        content_binding,
    })?)
}

// The random MAC key is sealed inside the payload. Publishing this tag does
// not publish a salt/key for offline password guesses. A fresh import freezes
// this tag before IPC so verified metadata can prove exact source content.
fn content_binding(bytes: &[u8]) -> Result<String> {
    use hmac::{Hmac, Mac};
    if bytes.len() < 46 {
        return Err(Error::Security("invalid protected login content".into()));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&bytes[8..40])
        .map_err(|_| Error::Security("login content MAC initialization failed".into()))?;
    mac.update(b"cameroncooper.keychain/login-content/v1\0");
    mac.update(&bytes[..8]);
    mac.update(&bytes[40..]);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

struct LoginView<'a> {
    password: &'a str,
    notes: &'a str,
    totp_uri: &'a str,
}
impl<'a> LoginView<'a> {
    fn parse(bytes: &'a [u8], metadata: &LoginMetadata, expected_content: &str) -> Result<Self> {
        let invalid = || Error::Security("invalid protected login content".into());
        if bytes.len() < 46 || &bytes[..8] != MAGIC || content_binding(bytes)? != expected_content {
            return Err(invalid());
        }
        let mut fields = [""; 3];
        let mut offset = 46usize;
        for (index, field) in fields.iter_mut().enumerate() {
            let length = usize::from(u16::from_be_bytes([
                bytes[40 + 2 * index],
                bytes[41 + 2 * index],
            ]));
            let end = offset.checked_add(length).ok_or_else(invalid)?;
            *field = std::str::from_utf8(bytes.get(offset..end).ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            offset = end;
        }
        if offset != bytes.len()
            || metadata.has_password == fields[0].is_empty()
            || metadata.has_notes == fields[1].is_empty()
            || metadata.has_totp == fields[2].is_empty()
            || (!fields[2].is_empty() && !crate::totp::is_valid(fields[2]))
        {
            return Err(invalid());
        }
        Ok(Self {
            password: fields[0],
            notes: fields[1],
            totp_uri: fields[2],
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RevealField {
    Password,
    Notes,
    Totp,
    All,
}

#[derive(Serialize)]
pub(super) struct RevealOutput<'a> {
    id: &'a str,
    revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp: Option<crate::totp::GeneratedCode>,
}
impl<'a> RevealOutput<'a> {
    fn selected(
        record: &'a registry::LoginRecord,
        view: &LoginView<'a>,
        field: RevealField,
        at: u64,
    ) -> Result<Self> {
        Ok(Self {
            id: &record.metadata.id,
            revision: record.revision,
            password: matches!(field, RevealField::Password | RevealField::All)
                .then_some(view.password),
            notes: matches!(field, RevealField::Notes | RevealField::All).then_some(view.notes),
            totp: if matches!(field, RevealField::Totp | RevealField::All)
                && !view.totp_uri.is_empty()
            {
                Some(crate::totp::generate(view.totp_uri, at).ok_or_else(|| {
                    Error::Security("invalid protected TOTP configuration or clock".into())
                })?)
            } else {
                None
            },
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginSelection {
    pub id: String,
    pub revision: u64,
    pub content_binding: String,
}

/// Intentionally revealed fields in the requesting process. Owned response
/// strings and codes wipe on drop; no seed/private-key field is accepted.
#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct RevealedLogin {
    pub id: String,
    pub revision: u64,
    pub password: Option<zeroize::Zeroizing<String>>,
    pub notes: Option<zeroize::Zeroizing<String>>,
    pub totp: Option<crate::totp::GeneratedCode>,
}
pub fn reveal(
    socket: &Path,
    selection: &LoginSelection,
    field: RevealField,
    canceled: Arc<AtomicBool>,
) -> Result<RevealedLogin> {
    keychain_sep_driver::memory::make_process_nondumpable()
        .map_err(|e| Error::io("login reveal memory protection", e))?;
    let reply: RevealedLogin = super::call_typed_cancelable(
        socket,
        Operation::RevealLogin {
            selection: selection.clone(),
            field,
        },
        canceled,
    )?;
    validate_reply(reply, selection, field)
}
fn validate_reply(
    reply: RevealedLogin,
    selection: &LoginSelection,
    field: RevealField,
) -> Result<RevealedLogin> {
    if reply.id != selection.id
        || reply.revision != selection.revision
        || reply.revision == 0
        || (reply.password.is_some() != matches!(field, RevealField::Password | RevealField::All))
        || (reply.notes.is_some() != matches!(field, RevealField::Notes | RevealField::All))
        || (!matches!(field, RevealField::Totp | RevealField::All) && reply.totp.is_some())
        || (field == RevealField::Totp && reply.totp.is_none())
    {
        return Err(Error::Security("invalid selected login response".into()));
    }
    Ok(reply)
}

impl Broker {
    pub(super) fn execute_login(
        &self,
        id: Uuid,
        operation: Operation,
        canceled: Arc<AtomicBool>,
        session: ActiveSession,
    ) -> Result<serde_json::Value> {
        match operation {
            Operation::ListLogins => Ok(serde_json::to_value(
                self.registry.login_metadata(self.owner)?,
            )?),
            Operation::LoginProtectionState { record } => Ok(serde_json::to_value(
                self.registry.login_state(&record, self.owner)?,
            )?),
            Operation::DiscardStagedLogin { record, revision } => {
                self.registry
                    .discard_staged_login(&record, self.owner, revision)?;
                Ok(serde_json::json!({"discarded":true}))
            }
            Operation::ImportLogin { import } => {
                if !self.allow_item_decrypt {
                    return Err(ProviderError::UnsupportedPolicy.into());
                }
                if canceled.load(Ordering::Acquire) || !session.valid() {
                    return Err(ProviderError::Canceled.into());
                }
                let revision = self.registry.import_login(self.owner, *import)?;
                Ok(serde_json::json!({"revision":revision,"verified":false}))
            }
            Operation::ReplaceStagedLogin {
                expected_content,
                import,
            } => {
                if !self.allow_item_decrypt {
                    return Err(ProviderError::UnsupportedPolicy.into());
                }
                if canceled.load(Ordering::Acquire) || !session.valid() {
                    return Err(ProviderError::Canceled.into());
                }
                let revision =
                    self.registry
                        .replace_staged_login(self.owner, &expected_content, *import)?;
                Ok(serde_json::json!({"revision":revision,"verified":false}))
            }
            Operation::VerifyLogin { selection } => {
                if !self.allow_item_decrypt {
                    return Err(ProviderError::UnsupportedPolicy.into());
                }
                let record = self
                    .registry
                    .login_verification_record(&selection.id, self.owner)?;
                if record.revision != selection.revision
                    || record.content_binding != selection.content_binding
                {
                    return Err(Error::Refused(
                        "selected login changed before verification".into(),
                    ));
                }
                let authorization = self.native_authorization(
                    Presentation {
                        id,
                        application: "Keychain".into(),
                        action: format!("Verify protection for {}", record.metadata.domain),
                        account: record.metadata.username.clone(),
                    },
                    canceled,
                    session,
                    false,
                )?;
                self.with_login(&record, &authorization, |_| {
                    authorization.check()?;
                    self.registry.commit_verified_login(&record)?;
                    Ok(())
                })?;
                authorization.check()?;
                Ok(serde_json::json!({"revision":record.revision,"verified":true}))
            }
            _ => Err(Error::InvalidData("invalid login operation".into())),
        }
    }
    fn with_login<T>(
        &self,
        record: &registry::LoginRecord,
        authorization: &super::native::NativeAuthorization,
        operation: impl FnOnce(&LoginView<'_>) -> Result<T>,
    ) -> Result<T> {
        authorization.check()?;
        let key = self.registry.item_key()?;
        if key.reference().key_id != record.recipient_id {
            return Err(Error::Security("wrong login recipient".into()));
        }
        let binding = login_binding(
            self.owner,
            record.revision,
            &record.recipient_id,
            &record.metadata,
            &record.content_binding,
        )?;
        let mut memory = SecretBuffer::new().map_err(|e| Error::io("login plaintext memory", e))?;
        let length = key.decrypt_selected(
            &self.device,
            &record.sealed,
            memory.as_mut_array(),
            authorization.deadline,
            |guidance| authorization.progress(guidance),
        )?;
        authorization.check()?;
        let bytes = envelope::item_view(memory.as_array(), length, &binding)?;
        let view = LoginView::parse(bytes, &record.metadata, &record.content_binding)?;
        authorization.status("Finishing verification…")?;
        let result = operation(&view);
        drop(memory);
        authorization.check()?;
        result
    }
    fn reveal_login(
        &self,
        id: Uuid,
        selection: &LoginSelection,
        field: RevealField,
        canceled: Arc<AtomicBool>,
        deliver: impl FnOnce(&RevealOutput<'_>, &dyn Fn() -> Result<()>) -> Result<()>,
    ) -> Result<()> {
        if !self.allow_item_decrypt {
            return Err(ProviderError::UnsupportedPolicy.into());
        }
        let session = ActiveSession::for_owner(self.owner)?;
        let _active = self
            .active
            .try_lock()
            .map_err(|_| Error::Refused("another key operation is active".into()))?;
        let selected = self.registry.select_login(self.owner, selection)?;
        let record = selected.record();
        if field == RevealField::Totp && !record.metadata.has_totp {
            return Err(Error::Refused("login has no TOTP configured".into()));
        }
        let action = match field {
            RevealField::Password => "Reveal password",
            RevealField::Notes => "Reveal notes",
            RevealField::Totp => "Generate verification code",
            RevealField::All => "Reveal password, notes and verification code",
        };
        let authorization = self.native_authorization(
            Presentation {
                id,
                application: "Keychain".into(),
                action: format!("{action} for {}", record.metadata.domain),
                account: record.metadata.username.clone(),
            },
            canceled,
            session,
            false,
        )?;
        self.with_login(record, &authorization, |view| {
            self.registry
                .with_verified_login(&selected, &|| authorization.check(), || {
                    let at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| Error::Security("system clock predates Unix epoch".into()))?
                        .as_secs();
                    let output = RevealOutput::selected(record, view, field, at)?;
                    deliver(&output, &|| authorization.check())
                })
        })
    }

    pub(super) fn handle_reveal(
        &self,
        stream: &mut UnixStream,
        id: Uuid,
        selection: &LoginSelection,
        field: RevealField,
        canceled: Arc<AtomicBool>,
    ) -> Result<()> {
        let mut delivery_started = false;
        let result = self.reveal_login(id, selection, field, canceled.clone(), |output, check| {
            write_reveal_response(stream, id, output, check, &mut delivery_started)
        });
        match result {
            Ok(()) => Ok(()),
            Err(error) if delivery_started || canceled.load(Ordering::Acquire) => Err(error), // Never append an error to a partial secret frame.
            Err(error) => write_frame(
                stream,
                &Response::<serde_json::Value> {
                    version: 1,
                    id,
                    result: None,
                    error: Some(failure(error)),
                },
            )
            .map_err(|e| Error::io("login reply", e)),
        }
    }
}

fn write_reveal_response(
    stream: &mut UnixStream,
    id: Uuid,
    output: &RevealOutput<'_>,
    check: &dyn Fn() -> Result<()>,
    delivery_started: &mut bool,
) -> Result<()> {
    #[derive(Serialize)]
    struct Reply<'a, T> {
        version: u32,
        id: Uuid,
        result: &'a T,
        error: Option<()>,
    }
    let mut writer = SecretWriter::new()?;
    serde_json::to_writer(
        &mut writer,
        &Reply {
            version: 1,
            id,
            result: output,
            error: None,
        },
    )?;
    check()?;
    *delivery_started = true;
    stream
        .write_all(&(writer.length as u32).to_le_bytes())
        .map_err(|e| Error::io("login reply", e))?;
    for chunk in writer.bytes().chunks(4096) {
        check()?;
        stream
            .write_all(chunk)
            .map_err(|e| Error::io("login reply", e))?;
    }
    check()
}

// Maximum plaintext is <4015 bytes; even worst-case JSON escaping fits here.
struct SecretWriter {
    memory: LockedBuffer<32768>,
    length: usize,
}
impl SecretWriter {
    fn new() -> Result<Self> {
        Ok(Self {
            memory: LockedBuffer::new().map_err(|e| Error::io("login reply memory", e))?,
            length: 0,
        })
    }
    fn bytes(&self) -> &[u8] {
        &self.memory.as_array()[..self.length]
    }
}
impl Write for SecretWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > 32768 - self.length {
            return Err(io::Error::other("login reply exceeds limit"));
        }
        self.memory.as_mut_array()[self.length..self.length + bytes.len()].copy_from_slice(bytes);
        self.length += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    pub(crate) fn item() -> Credential {
        Credential {
            protected: false,
            id: Uuid::new_v4().to_string(),
            domain: "example.com".into(),
            username: "Synthetic login".into(),
            title: "Test".into(),
            modified_at: 2.0,
            last_used: 1.0,
            password: "synthetic-password".into(),
            notes: "private synthetic notes".into(),
            totp_uri: "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8".into(),
        }
    }
    pub(crate) fn recipient() -> Result<registry::Recipient> {
        let key = p256::SecretKey::from_slice(&[7; 32])
            .map_err(|_| Error::Security("test key".into()))?;
        Ok(registry::Recipient {
            id: Uuid::new_v4().to_string(),
            public_sec1: STANDARD.encode(key.public_key().to_encoded_point(false).as_bytes()),
        })
    }
    pub(crate) fn decrypt(sealed: &[u8]) -> Result<(SecretBuffer, usize)> {
        use aes_gcm::aead::{AeadInPlace, KeyInit, consts::U16};
        let key = p256::SecretKey::from_slice(&[7; 32])
            .map_err(|_| Error::Security("test key".into()))?;
        let public = p256::PublicKey::from_sec1_bytes(&sealed[..65])
            .map_err(|_| Error::Security("test point".into()))?;
        let shared = p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), public.as_affine());
        let mut material = zeroize::Zeroizing::new([0u8; 64]);
        for index in 1u32..=2 {
            let mut hash = Sha256::new();
            hash.update(shared.raw_secret_bytes());
            hash.update(index.to_be_bytes());
            hash.update(&sealed[..65]);
            let block = zeroize::Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
            material[(index as usize - 1) * 32..index as usize * 32].copy_from_slice(&block[..]);
        }
        let cipher = aes_gcm::AesGcm::<aes::Aes256, U16>::new_from_slice(&material[..32])
            .map_err(|_| Error::Security("test cipher".into()))?;
        let length = sealed.len() - 81;
        let mut memory = SecretBuffer::new().map_err(|e| Error::io("test memory", e))?;
        memory.as_mut_array()[..length].copy_from_slice(&sealed[65..sealed.len() - 16]);
        cipher
            .decrypt_in_place_detached(
                aes_gcm::Nonce::<U16>::from_slice(&material[32..48]),
                b"",
                &mut memory.as_mut_array()[..length],
                aes_gcm::Tag::from_slice(&sealed[sealed.len() - 16..]),
            )
            .map_err(|_| Error::Security("test decrypt".into()))?;
        Ok((memory, length))
    }
    pub(crate) fn validate(record: &registry::LoginRecord) -> Result<()> {
        let (memory, length) = decrypt(&record.sealed)?;
        let binding = login_binding(
            record.owner,
            record.revision,
            &record.recipient_id,
            &record.metadata,
            &record.content_binding,
        )?;
        let bytes = envelope::item_view(memory.as_array(), length, &binding)?;
        LoginView::parse(bytes, &record.metadata, &record.content_binding)?;
        Ok(())
    }
    fn record(import: LoginImport) -> registry::LoginRecord {
        registry::LoginRecord {
            version: 1,
            owner: 1001,
            revision: import.expected_revision + 1,
            recipient_id: import.recipient_id,
            metadata: import.metadata,
            content_binding: import.content_binding,
            sealed: import.sealed,
            verified: true,
        }
    }
    #[test]
    fn selected_login_roundtrip_reveals_only_requested_fields_and_never_the_seed() -> Result<()> {
        let item = item();
        let import = LoginImport::seal(1001, &recipient()?, 0, &item)?;
        let request = serde_json::to_string(&import)?;
        for secret in [&item.password, &item.notes, &item.totp_uri] {
            assert!(!request.contains(secret));
        }
        let record = record(import);
        let (memory, length) = decrypt(&record.sealed)?;
        let binding = login_binding(
            1001,
            1,
            &record.recipient_id,
            &record.metadata,
            &record.content_binding,
        )?;
        let bytes = envelope::item_view(memory.as_array(), length, &binding)?;
        let view = LoginView::parse(bytes, &record.metadata, &record.content_binding)?;
        for field in [
            RevealField::Password,
            RevealField::Notes,
            RevealField::Totp,
            RevealField::All,
        ] {
            let output = RevealOutput::selected(&record, &view, field, 59)?;
            let mut writer = SecretWriter::new()?;
            serde_json::to_writer(&mut writer, &output)?;
            let (mut server, mut client) =
                UnixStream::pair().map_err(|e| Error::io("test pair", e))?;
            let id = Uuid::new_v4();
            let mut started = false;
            write_reveal_response(&mut server, id, &output, &|| Ok(()), &mut started)?;
            let response: Response<RevealedLogin> =
                read_frame(&mut client).map_err(|e| Error::io("test reply", e))?;
            assert_eq!(response.id, id);
            assert!(response.error.is_none());
            let output = validate_reply(
                response
                    .result
                    .ok_or_else(|| Error::Security("test result missing".into()))?,
                &LoginSelection {
                    id: record.metadata.id.clone(),
                    revision: record.revision,
                    content_binding: record.content_binding.clone(),
                },
                field,
            )?;
            assert_eq!(
                output.password.as_ref().map(|value| value.as_str()),
                matches!(field, RevealField::Password | RevealField::All)
                    .then_some(item.password.as_str())
            );
            assert_eq!(
                output.notes.as_ref().map(|value| value.as_str()),
                matches!(field, RevealField::Notes | RevealField::All)
                    .then_some(item.notes.as_str())
            );
            assert_eq!(
                output.totp.as_ref().map(|value| value.code.as_str()),
                matches!(field, RevealField::Totp | RevealField::All).then_some("94287082")
            );
            assert!(
                !writer
                    .bytes()
                    .windows(32)
                    .any(|part| part == b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            );
        }
        assert!(serde_json::from_str::<RevealedLogin>(r#"{"id":"x","revision":1,"password":null,"notes":null,"totp":null,"totp_uri":"forbidden"}"#).is_err());
        assert!(
            serde_json::from_str::<Operation>(
                r#"{"kind":"reveal-login","record":"x","field":"totp-seed"}"#
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn reveal_client_refuses_wrong_record_fields_and_seed_shaped_payloads() -> Result<()> {
        let id = Uuid::new_v4().to_string();
        for json in [
            serde_json::json!({"id":id,"revision":0,"password":"synthetic"}),
            serde_json::json!({"id":"another-record","revision":1,"password":"synthetic"}),
            serde_json::json!({"id":id,"revision":1,"password":"synthetic","notes":"unrequested notes"}),
            serde_json::json!({"id":id,"revision":1,"password":"synthetic","totp":{"code":"123456","period":30,"expires":60}}),
        ] {
            let reply: RevealedLogin = serde_json::from_value(json)?;
            assert!(
                validate_reply(
                    reply,
                    &LoginSelection {
                        id: id.clone(),
                        revision: 1,
                        content_binding: "0".repeat(64)
                    },
                    RevealField::Password
                )
                .is_err()
            );
        }
        assert!(serde_json::from_str::<RevealedLogin>(r#"{"id":"x","revision":1,"totp":{"code":"123456","period":30,"expires":60,"secret":"forbidden"}}"#).is_err());
        let import = LoginImport::seal(1001, &recipient()?, 0, &item())?;
        let mut json = serde_json::to_value(&import)?;
        json["verified"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<LoginImport>(json).is_err());
        Ok(())
    }
    #[test]
    fn content_tags_are_randomized_and_bind_every_private_field() -> Result<()> {
        let item = item();
        let recipient = recipient()?;
        let first = LoginImport::seal(1001, &recipient, 0, &item)?;
        let second = LoginImport::seal(1001, &recipient, 0, &item)?;
        assert_ne!(first.content_binding, second.content_binding);
        let (memory, length) = decrypt(&first.sealed)?;
        let context = login_binding(
            1001,
            1,
            &first.recipient_id,
            &first.metadata,
            &first.content_binding,
        )?;
        let bytes = envelope::item_view(memory.as_array(), length, &context)?;
        for position in [8, 40, 46, bytes.len() - 1] {
            let mut changed = zeroize::Zeroizing::new(bytes.to_vec());
            changed[position] ^= 1;
            assert_ne!(content_binding(&changed)?, first.content_binding);
        }
        Ok(())
    }
    #[test]
    fn login_context_and_packed_content_refuse_substitution_and_malformed_fields() -> Result<()> {
        let mut item = item();
        let record = record(LoginImport::seal(1001, &recipient()?, 0, &item)?);
        let (memory, length) = decrypt(&record.sealed)?;
        for mutation in 0..6 {
            let mut changed = record.clone();
            match mutation {
                0 => changed.owner = 1002,
                1 => changed.revision += 1,
                2 => changed.recipient_id = Uuid::new_v4().to_string(),
                3 => changed.metadata.id = Uuid::new_v4().to_string(),
                4 => changed.metadata.domain = "other.example".into(),
                _ => changed.metadata.has_totp = false,
            }
            let binding = login_binding(
                changed.owner,
                changed.revision,
                &changed.recipient_id,
                &changed.metadata,
                &changed.content_binding,
            )?;
            assert!(envelope::item_view(memory.as_array(), length, &binding).is_err());
        }
        let binding = login_binding(
            1001,
            1,
            &record.recipient_id,
            &record.metadata,
            &record.content_binding,
        )?;
        let bytes = envelope::item_view(memory.as_array(), length, &binding)?;
        for mutation in 0..5 {
            let mut bad = zeroize::Zeroizing::new(bytes.to_vec());
            match mutation {
                0 => bad[0] ^= 1,
                1 => bad[40..42].copy_from_slice(&u16::MAX.to_be_bytes()),
                2 => bad.push(0),
                3 => bad[46] = 255,
                _ => {
                    bad.pop();
                }
            }
            assert!(LoginView::parse(&bad, &record.metadata, &content_binding(&bad)?).is_err());
        }
        item.totp_uri = "otpauth://totp/test?secret=INVALID0".into();
        assert!(LoginImport::seal(1001, &recipient()?, 0, &item).is_err());
        item.password = "x".repeat(4096);
        assert!(LoginImport::seal(1001, &recipient()?, 0, &item).is_err());
        Ok(())
    }
    #[test]
    fn secret_delivery_checks_cancellation_before_header_and_between_chunks() -> Result<()> {
        use std::cell::Cell;
        let item = item();
        let record = record(LoginImport::seal(1001, &recipient()?, 0, &item)?);
        let output = RevealOutput {
            id: &record.metadata.id,
            revision: 1,
            password: Some("synthetic"),
            notes: None,
            totp: None,
        };
        let (mut server, mut client) = UnixStream::pair().map_err(|e| Error::io("pair", e))?;
        client
            .set_nonblocking(true)
            .map_err(|e| Error::io("test", e))?;
        let mut started = false;
        assert!(
            write_reveal_response(
                &mut server,
                Uuid::new_v4(),
                &output,
                &|| Err(ProviderError::Canceled.into()),
                &mut started
            )
            .is_err()
        );
        assert!(!started);
        let mut bytes = [0; 32768];
        assert_eq!(
            client.read(&mut bytes).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        let large = "\0".repeat(3000);
        let output = RevealOutput {
            password: Some(&large),
            ..output
        };
        let checks = Cell::new(0);
        assert!(
            write_reveal_response(
                &mut server,
                Uuid::new_v4(),
                &output,
                &|| {
                    checks.set(checks.get() + 1);
                    if checks.get() >= 3 {
                        Err(ProviderError::Canceled.into())
                    } else {
                        Ok(())
                    }
                },
                &mut started
            )
            .is_err()
        );
        assert!(started);
        let length = client
            .read(&mut bytes)
            .map_err(|e| Error::io("test partial reply", e))?;
        assert!(length >= 4);
        let expected = u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| Error::Security("test header".into()))?,
        ) as usize;
        assert!(length < expected + 4);
        let mut writer = SecretWriter::new()?;
        writer
            .write_all(&[0; 32768])
            .map_err(|e| Error::io("test capacity", e))?;
        assert!(writer.write_all(&[0]).is_err());
        Ok(())
    }
}
