use std::fmt;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use ciborium::Value as CborValue;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use plist::{Dictionary, Value};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::model::PasskeyCredential;
use crate::security::{KeyUsage, SecurityBackend};
use crate::{Error, Result};

pub const ACCESS_GROUP: &str = "com.apple.webkit.webauthn";
const MAX_ATAG_BYTES: usize = 16 * 1024;
const MAX_CREDENTIAL_ID_BYTES: usize = 4096;
const MAX_USER_HANDLE_BYTES: usize = 64;
const MAX_TEXT_BYTES: usize = 4096;

pub struct RecoveredPasskey {
    pub record_id: String,
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub username: String,
    pub display_name: String,
    pub created_at: f64,
    pub modified_at: f64,
    private_x963: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for RecoveredPasskey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredPasskey")
            .field("record_id", &self.record_id)
            .field("rp_id", &self.rp_id)
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("credential_id", &"[REDACTED]")
            .field("user_handle", &"[REDACTED]")
            .field("private_x963", &"[REDACTED]")
            .finish()
    }
}

impl RecoveredPasskey {
    pub fn import(self, backend: &dyn SecurityBackend) -> Result<PasskeyCredential> {
        let signing_key =
            backend.import_p256_x963(KeyUsage::WebAuthnSigning, &self.private_x963)?;
        Ok(PasskeyCredential {
            id: self.record_id,
            rp_id: self.rp_id,
            credential_id: URL_SAFE_NO_PAD.encode(self.credential_id),
            user_handle: URL_SAFE_NO_PAD.encode(self.user_handle),
            username: self.username,
            display_name: self.display_name,
            created_at: self.created_at,
            modified_at: self.modified_at,
            signing_key,
        })
    }
}

pub fn from_item(record_id: &str, fields: &Dictionary) -> Result<Option<RecoveredPasskey>> {
    if field_text(fields, "agrp").as_deref() != Some(ACCESS_GROUP) {
        return Ok(None);
    }
    if let Some(class) = field_text(fields, "class") {
        if class != "keys" {
            return Err(invalid(record_id, format!("unexpected class {class:?}")));
        }
    }
    let rp_id = normalize_rp_id(&required_text(fields, record_id, "labl")?)
        .map_err(|message| invalid(record_id, message))?;
    let credential_id = required_data(fields, record_id, "alis")?;
    if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(invalid(
            record_id,
            "credential ID has an invalid length".into(),
        ));
    }
    let atag = required_data(fields, record_id, "atag")?;
    let user = decode_user_metadata(record_id, &atag)?;
    let private_x963 = required_data(fields, record_id, "v_Data")?;
    validate_private_key(record_id, &private_x963)?;

    Ok(Some(RecoveredPasskey {
        record_id: record_id.to_owned(),
        rp_id,
        credential_id,
        user_handle: user.id,
        username: user.name,
        display_name: user.display_name,
        created_at: to_unix(fields.get("cdat")),
        modified_at: to_unix(fields.get("mdat")),
        private_x963: Zeroizing::new(private_x963),
    }))
}

pub fn search<'a>(passkeys: &'a [PasskeyCredential], query: &str) -> Vec<&'a PasskeyCredential> {
    let query = query.trim().to_ascii_lowercase();
    let mut found: Vec<_> = passkeys
        .iter()
        .filter(|passkey| {
            query.is_empty()
                || passkey.id.to_ascii_lowercase().starts_with(&query)
                || passkey.rp_id.to_ascii_lowercase().contains(&query)
                || passkey.username.to_ascii_lowercase().contains(&query)
                || passkey.display_name.to_ascii_lowercase().contains(&query)
        })
        .collect();
    found.sort_by(|a, b| {
        b.modified_at
            .total_cmp(&a.modified_at)
            .then_with(|| a.rp_id.cmp(&b.rp_id))
            .then_with(|| a.username.cmp(&b.username))
    });
    found
}

pub fn credential_id(passkey: &PasskeyCredential) -> Result<Vec<u8>> {
    decode_base64url(&passkey.credential_id)
        .map_err(|_| Error::InvalidData("vault contains an invalid passkey credential ID".into()))
}

pub fn user_handle(passkey: &PasskeyCredential) -> Result<Vec<u8>> {
    decode_base64url(&passkey.user_handle)
        .map_err(|_| Error::InvalidData("vault contains an invalid passkey user handle".into()))
}

pub fn credential_fingerprint(passkey: &PasskeyCredential) -> Result<String> {
    let digest = Sha256::digest(credential_id(passkey)?);
    Ok(hex::encode(&digest[..8]))
}

pub struct SignedAssertion {
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Sign the authenticator-controlled portion of a WebAuthn assertion.
///
/// The caller supplies the browser-generated clientDataHash. User verification is deliberately
/// explicit so a future browser service cannot claim UV unless a real verifier approved it.
pub fn sign_assertion(
    passkey: &PasskeyCredential,
    client_data_hash: &[u8],
    user_present: bool,
    user_verified: bool,
    backend: &dyn SecurityBackend,
) -> Result<SignedAssertion> {
    if client_data_hash.len() != 32 {
        return Err(Error::InvalidData(
            "WebAuthn clientDataHash must be 32 bytes".into(),
        ));
    }
    if user_verified && !user_present {
        return Err(Error::Security(
            "WebAuthn user verification cannot be asserted without user presence".into(),
        ));
    }
    let mut flags = 0x08 | 0x10; // Backup eligible and currently backed up (synced passkey).
    if user_present {
        flags |= 0x01;
    }
    if user_verified {
        flags |= 0x04;
    }
    let mut authenticator_data = Vec::with_capacity(37);
    authenticator_data.extend_from_slice(&Sha256::digest(passkey.rp_id.as_bytes()));
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
    let mut signed = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    signed.extend_from_slice(&authenticator_data);
    signed.extend_from_slice(client_data_hash);
    let signature = backend.sign_p256_sha256(&passkey.signing_key, &signed)?;
    Ok(SignedAssertion {
        authenticator_data,
        signature,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnAssertion {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub credential_type: &'static str,
    pub response: AssertionResponse,
    pub client_extension_results: serde_json::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

/// Build a complete assertion for diagnostics and direct relying-party integration.
/// Browser integration should instead call `sign_assertion` with its own clientDataHash.
pub fn assertion_for_origin(
    passkey: &PasskeyCredential,
    challenge: &str,
    origin: &str,
    backend: &dyn SecurityBackend,
) -> Result<WebAuthnAssertion> {
    let challenge_bytes = decode_base64url(challenge)
        .map_err(|_| Error::InvalidData("challenge is not base64url".into()))?;
    if !(16..=4096).contains(&challenge_bytes.len()) {
        return Err(Error::InvalidData(
            "WebAuthn challenge must contain 16 to 4096 bytes".into(),
        ));
    }
    let canonical_challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);
    let canonical_origin = validate_origin_for_rp(origin, &passkey.rp_id)?;
    let client_data = serde_json::to_vec(&serde_json::json!({
        "type": "webauthn.get",
        "challenge": canonical_challenge,
        "origin": canonical_origin,
        "crossOrigin": false,
    }))?;
    let assertion = sign_assertion(passkey, &Sha256::digest(&client_data), true, false, backend)?;
    Ok(WebAuthnAssertion {
        id: passkey.credential_id.clone(),
        raw_id: passkey.credential_id.clone(),
        credential_type: "public-key",
        response: AssertionResponse {
            client_data_json: URL_SAFE_NO_PAD.encode(client_data),
            authenticator_data: URL_SAFE_NO_PAD.encode(assertion.authenticator_data),
            signature: URL_SAFE_NO_PAD.encode(assertion.signature),
            user_handle: passkey.user_handle.clone(),
        },
        client_extension_results: serde_json::json!({}),
    })
}

fn validate_origin_for_rp(origin: &str, rp_id: &str) -> Result<String> {
    let url = url::Url::parse(origin)
        .map_err(|_| Error::InvalidData("WebAuthn origin is not a valid URL".into()))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(Error::Security(
            "WebAuthn origin must be an HTTPS origin without credentials, path, query, or fragment"
                .into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error::InvalidData("WebAuthn origin has no host".into()))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
        return Err(Error::Security(format!(
            "origin host {host} is outside relying party {rp_id}"
        )));
    }
    Ok(url.origin().ascii_serialization())
}

struct UserMetadata {
    id: Vec<u8>,
    name: String,
    display_name: String,
}

fn decode_user_metadata(record_id: &str, bytes: &[u8]) -> Result<UserMetadata> {
    if bytes.is_empty() || bytes.len() > MAX_ATAG_BYTES {
        return Err(invalid(record_id, "atag has an invalid length".into()));
    }
    let mut reader = Cursor::new(bytes);
    let value: CborValue = ciborium::de::from_reader(&mut reader)
        .map_err(|_| invalid(record_id, "atag is not valid CBOR".into()))?;
    if reader.position() != bytes.len() as u64 {
        return Err(invalid(record_id, "atag has trailing CBOR data".into()));
    }
    let CborValue::Map(entries) = value else {
        return Err(invalid(record_id, "atag is not a CBOR map".into()));
    };
    let mut id = None;
    let mut name = None;
    let mut display_name = None;
    for (key, value) in entries {
        let CborValue::Text(key) = key else {
            return Err(invalid(record_id, "atag contains a non-text key".into()));
        };
        match key.as_str() {
            "id" => set_once(
                &mut id,
                match value {
                    CborValue::Bytes(value) => value,
                    _ => return Err(invalid(record_id, "atag id is not bytes".into())),
                },
                record_id,
                "id",
            )?,
            "name" => set_once(
                &mut name,
                match value {
                    CborValue::Text(value) => value,
                    _ => return Err(invalid(record_id, "atag name is not text".into())),
                },
                record_id,
                "name",
            )?,
            "displayName" => set_once(
                &mut display_name,
                match value {
                    CborValue::Text(value) => value,
                    _ => {
                        return Err(invalid(record_id, "atag displayName is not text".into()));
                    }
                },
                record_id,
                "displayName",
            )?,
            _ => {}
        }
    }
    let id = id.ok_or_else(|| invalid(record_id, "atag has no user id".into()))?;
    if id.is_empty() || id.len() > MAX_USER_HANDLE_BYTES {
        return Err(invalid(
            record_id,
            "atag user id has an invalid length".into(),
        ));
    }
    let name = name.ok_or_else(|| invalid(record_id, "atag has no user name".into()))?;
    let display_name = display_name.unwrap_or_else(|| name.clone());
    for (field, value) in [("name", &name), ("displayName", &display_name)] {
        if value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
            return Err(invalid(
                record_id,
                format!("atag {field} contains invalid text"),
            ));
        }
    }
    Ok(UserMetadata {
        id,
        name,
        display_name,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, record_id: &str, field: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        return Err(invalid(
            record_id,
            format!("atag contains duplicate {field}"),
        ));
    }
    Ok(())
}

fn validate_private_key(record_id: &str, private_x963: &[u8]) -> Result<()> {
    if private_x963.len() != 97 || private_x963.first() != Some(&4) {
        return Err(invalid(
            record_id,
            "private key is not a 97-byte P-256 X9.63 value".into(),
        ));
    }
    let secret = SecretKey::from_slice(&private_x963[65..])
        .map_err(|_| invalid(record_id, "private key has an invalid scalar".into()))?;
    if secret.public_key().to_encoded_point(false).as_bytes() != &private_x963[..65] {
        return Err(invalid(
            record_id,
            "private key scalar does not match its public point".into(),
        ));
    }
    Ok(())
}

fn required_text(fields: &Dictionary, record_id: &str, name: &str) -> Result<String> {
    let value = field_text(fields, name)
        .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT_BYTES)
        .ok_or_else(|| invalid(record_id, format!("missing or invalid {name}")))?;
    if value.chars().any(char::is_control) {
        return Err(invalid(record_id, format!("{name} contains control text")));
    }
    Ok(value)
}

fn field_text(fields: &Dictionary, name: &str) -> Option<String> {
    match fields.get(name) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Data(value)) => String::from_utf8(value.clone()).ok(),
        _ => None,
    }
}

fn required_data(fields: &Dictionary, record_id: &str, name: &str) -> Result<Vec<u8>> {
    fields
        .get(name)
        .and_then(Value::as_data)
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid(record_id, format!("missing or invalid {name}")))
}

fn normalize_rp_id(value: &str) -> std::result::Result<String, String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 || value.contains(['/', ':']) {
        return Err("relying-party ID is not a host".into());
    }
    url::Host::parse(&value)
        .map(|host| host.to_string())
        .map_err(|_| "relying-party ID is not a valid host".into())
}

fn decode_base64url(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
}

fn to_unix(value: Option<&Value>) -> f64 {
    const APPLE_EPOCH: f64 = 978_307_200.0;
    match value {
        Some(Value::Date(date)) => {
            let time: SystemTime = (*date).into();
            time.duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs_f64())
                .unwrap_or_default()
        }
        Some(Value::Real(value)) => {
            if *value > 0.0 && *value < 1e9 {
                value + APPLE_EPOCH
            } else {
                *value
            }
        }
        Some(Value::Integer(value)) => value
            .as_signed()
            .map(|value| value as f64)
            .or_else(|| value.as_unsigned().map(|value| value as f64))
            .map(|value| {
                if value > 0.0 && value < 1e9 {
                    value + APPLE_EPOCH
                } else {
                    value
                }
            })
            .unwrap_or_default(),
        _ => 0.0,
    }
}

fn invalid(record_id: &str, message: String) -> Error {
    Error::InvalidData(format!("passkey {record_id}: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::AppPaths;
    use crate::security::SoftwareFileBackend;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    fn fixture_fields() -> Dictionary {
        let secret =
            SecretKey::from_slice(&[7_u8; 32]).unwrap_or_else(|error| panic!("test key: {error}"));
        let mut private = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        private.extend_from_slice(&secret.to_bytes());
        let metadata = CborValue::Map(vec![
            (
                CborValue::Text("id".into()),
                CborValue::Bytes(vec![1, 2, 3]),
            ),
            (
                CborValue::Text("name".into()),
                CborValue::Text("alice@example.com".into()),
            ),
            (
                CborValue::Text("displayName".into()),
                CborValue::Text("Alice".into()),
            ),
        ]);
        let mut atag = Vec::new();
        ciborium::ser::into_writer(&metadata, &mut atag)
            .unwrap_or_else(|error| panic!("CBOR: {error}"));
        Dictionary::from_iter([
            ("agrp".to_owned(), Value::String(ACCESS_GROUP.into())),
            ("class".to_owned(), Value::String("keys".into())),
            ("labl".to_owned(), Value::String("WebAuthn.IO".into())),
            ("alis".to_owned(), Value::Data(vec![9, 8, 7])),
            ("atag".to_owned(), Value::Data(atag)),
            ("v_Data".to_owned(), Value::Data(private)),
        ])
    }

    #[test]
    fn decodes_and_imports_an_apple_passkey() {
        let recovered = from_item("record", &fixture_fields())
            .unwrap_or_else(|error| panic!("decode: {error}"))
            .unwrap_or_else(|| panic!("not a passkey"));
        assert_eq!(recovered.rp_id, "webauthn.io");
        assert_eq!(recovered.credential_id, [9, 8, 7]);
        assert_eq!(recovered.user_handle, [1, 2, 3]);
        assert_eq!(recovered.username, "alice@example.com");

        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths =
            AppPaths::for_test(dir.path()).unwrap_or_else(|error| panic!("test paths: {error}"));
        let backend = SoftwareFileBackend::new(paths);
        let stored = recovered
            .import(&backend)
            .unwrap_or_else(|error| panic!("import: {error}"));
        assert_eq!(stored.credential_id, "CQgH");

        let client_hash = Sha256::digest(b"client data");
        let assertion = sign_assertion(&stored, &client_hash, true, false, &backend)
            .unwrap_or_else(|error| panic!("assertion: {error}"));
        assert_eq!(assertion.authenticator_data.len(), 37);
        assert_eq!(assertion.authenticator_data[32], 0x19);
        let public = backend
            .public_x963(&stored.signing_key)
            .unwrap_or_else(|error| panic!("public key: {error}"));
        let verifying = VerifyingKey::from_sec1_bytes(&public)
            .unwrap_or_else(|error| panic!("verifying key: {error}"));
        let signature = Signature::from_der(&assertion.signature)
            .unwrap_or_else(|error| panic!("signature: {error}"));
        let mut signed = assertion.authenticator_data;
        signed.extend_from_slice(&client_hash);
        assert!(verifying.verify(&signed, &signature).is_ok());
    }

    #[test]
    fn rejects_a_private_scalar_that_does_not_match_the_public_point() {
        let mut fields = fixture_fields();
        let Some(Value::Data(private)) = fields.get_mut("v_Data") else {
            panic!("private data");
        };
        private[96] ^= 1;
        assert!(from_item("record", &fields).is_err());
    }

    #[test]
    fn origin_is_bound_to_the_relying_party() {
        assert_eq!(
            validate_origin_for_rp("https://login.webauthn.io", "webauthn.io")
                .unwrap_or_else(|error| panic!("origin: {error}")),
            "https://login.webauthn.io"
        );
        assert!(validate_origin_for_rp("https://webauthn.io.evil.test", "webauthn.io").is_err());
        assert!(validate_origin_for_rp("http://webauthn.io", "webauthn.io").is_err());
    }

    #[test]
    fn assertion_json_uses_webauthn_acronym_spelling() {
        let value = serde_json::to_value(WebAuthnAssertion {
            id: "id".into(),
            raw_id: "id".into(),
            credential_type: "public-key",
            response: AssertionResponse {
                client_data_json: "client".into(),
                authenticator_data: "authenticator".into(),
                signature: "signature".into(),
                user_handle: "user".into(),
            },
            client_extension_results: serde_json::json!({}),
        })
        .unwrap_or_else(|error| panic!("JSON: {error}"));
        let response = value
            .get("response")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("response object"));
        assert!(response.contains_key("clientDataJSON"));
        assert!(!response.contains_key("clientDataJson"));
    }
}
