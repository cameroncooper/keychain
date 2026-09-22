//! Security boundary for Chromium's `webAuthenticationProxy` adapter.
//!
//! Chromium injects the calling origin into
//! `extensions.remoteDesktopClientOverride` before forwarding a request to the extension. The
//! native host accepts no separate, extension-supplied origin and requires that injected value on
//! every request.

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::model::{PasskeyCredential, VaultState};
use crate::passkey;
use crate::security::SecurityBackend;
use crate::store::StateStore;
use crate::{Error, Result};

pub const NATIVE_HOST_NAME: &str = "cameroncooper.keychain";
pub const MAX_NATIVE_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_DETAILS_BYTES: usize = 256 * 1024;
const MAX_ALLOW_CREDENTIALS: usize = 256;
const MAX_CANDIDATES: usize = 64;
const MAX_CREDENTIAL_ID_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
enum HostRequest {
    Inspect {
        version: u32,
        #[serde(rename = "requestDetailsJson")]
        request_details_json: String,
    },
    Assert {
        version: u32,
        #[serde(rename = "requestDetailsJson")]
        request_details_json: String,
        #[serde(rename = "passkeyId")]
        passkey_id: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HostReply {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<HostResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<HostError>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum HostResult {
    Inspection {
        #[serde(rename = "rpId")]
        rp_id: String,
        origin: String,
        #[serde(rename = "userVerification")]
        user_verification: UserVerification,
        candidates: Vec<Candidate>,
    },
    Assertion {
        #[serde(rename = "responseJson")]
        response_json: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum UserVerification {
    Discouraged,
    Preferred,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Candidate {
    id: String,
    username: String,
    display_name: String,
}

#[derive(Debug, Serialize)]
struct HostError {
    name: &'static str,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyRequest {
    challenge: String,
    rp_id: String,
    #[serde(default)]
    allow_credentials: Vec<CredentialDescriptor>,
    #[serde(default = "default_user_verification")]
    user_verification: String,
    extensions: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct CredentialDescriptor {
    #[serde(rename = "type")]
    credential_type: String,
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemoteDesktopClientOverride {
    origin: String,
    same_origin_with_ancestors: bool,
}

struct RequestContext {
    challenge: String,
    rp_id: String,
    origin: String,
    user_verification: UserVerification,
    allowed_credential_ids: BTreeSet<String>,
}

/// Convert one unframed native-messaging request into a reply. Application errors are encoded in
/// the reply so the extension can complete the corresponding WebAuthn request instead of hanging.
pub fn reply_for_message(
    message: &[u8],
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> serde_json::Value {
    match handle_message(message, backend, store) {
        Ok(result) => serde_json::to_value(HostReply {
            ok: true,
            result: Some(result),
            error: None,
        })
        .unwrap_or_else(|_| fallback_serialization_error()),
        Err(error) => error_reply(&error),
    }
}

fn handle_message(
    message: &[u8],
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<HostResult> {
    if message.len() > MAX_NATIVE_MESSAGE_BYTES {
        return Err(Error::InvalidData(format!(
            "native message exceeds the {MAX_NATIVE_MESSAGE_BYTES}-byte limit"
        )));
    }
    let request: HostRequest = serde_json::from_slice(message)?;
    let (version, details) = match &request {
        HostRequest::Inspect {
            version,
            request_details_json,
        }
        | HostRequest::Assert {
            version,
            request_details_json,
            ..
        } => (*version, request_details_json.as_str()),
    };
    if version != 1 {
        return Err(Error::InvalidData(format!(
            "unsupported browser host protocol version {version}"
        )));
    }
    let context = RequestContext::parse(details)?;
    let vault = store
        .load_vault()?
        .ok_or_else(|| Error::Config("vault is empty; run `keychain sync`".into()))?;
    let candidates = context.candidates(&vault)?;
    if candidates.is_empty() {
        return Err(Error::Refused(format!(
            "no local passkey matches relying party {}",
            context.rp_id
        )));
    }

    match request {
        HostRequest::Inspect { .. } => Ok(HostResult::Inspection {
            rp_id: context.rp_id,
            origin: context.origin,
            user_verification: context.user_verification,
            candidates: candidates
                .into_iter()
                .map(|passkey| Candidate {
                    id: passkey.id.clone(),
                    username: passkey.username.clone(),
                    display_name: passkey.display_name.clone(),
                })
                .collect(),
        }),
        HostRequest::Assert { passkey_id, .. } => {
            let passkey = candidates
                .into_iter()
                .find(|candidate| candidate.id == passkey_id)
                .ok_or_else(|| {
                    Error::Refused(
                        "the selected passkey is not eligible for this browser request".into(),
                    )
                })?;
            let assertion = passkey::assertion_for_origin(
                passkey,
                &context.challenge,
                &context.origin,
                backend,
            )?;
            Ok(HostResult::Assertion {
                response_json: serde_json::to_string(&assertion)?,
            })
        }
    }
}

impl RequestContext {
    fn parse(details: &str) -> Result<Self> {
        if details.len() > MAX_REQUEST_DETAILS_BYTES {
            return Err(Error::InvalidData(format!(
                "WebAuthn request exceeds the {MAX_REQUEST_DETAILS_BYTES}-byte limit"
            )));
        }
        let mut request: ProxyRequest = serde_json::from_str(details)?;
        let override_value = request
            .extensions
            .remove("remoteDesktopClientOverride")
            .ok_or_else(|| {
                Error::Security(
                    "browser request is missing Chromium's caller-origin override".into(),
                )
            })?;
        if !request.extensions.is_empty() {
            let names = request
                .extensions
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::InvalidData(format!(
                "unsupported WebAuthn extensions: {names}"
            )));
        }
        let caller: RemoteDesktopClientOverride = serde_json::from_value(override_value)?;
        if !caller.same_origin_with_ancestors {
            return Err(Error::Security(
                "cross-origin iframe WebAuthn requests are not supported".into(),
            ));
        }
        let rp_id = passkey::normalize_rp_id(&request.rp_id).map_err(|message| {
            Error::InvalidData(format!("invalid relying-party ID: {message}"))
        })?;
        let origin = passkey::validate_origin_for_rp(&caller.origin, &rp_id)?;

        let challenge = canonical_base64url(&request.challenge, "challenge", 16, 4096)?;
        if request.allow_credentials.len() > MAX_ALLOW_CREDENTIALS {
            return Err(Error::InvalidData(format!(
                "allowCredentials exceeds the {MAX_ALLOW_CREDENTIALS}-entry limit"
            )));
        }
        let mut allowed_credential_ids = BTreeSet::new();
        for descriptor in request.allow_credentials {
            if descriptor.credential_type != "public-key" {
                return Err(Error::InvalidData(
                    "allowCredentials contains a non-public-key credential".into(),
                ));
            }
            allowed_credential_ids.insert(canonical_base64url(
                &descriptor.id,
                "credential ID",
                1,
                MAX_CREDENTIAL_ID_BYTES,
            )?);
        }
        let user_verification = match request.user_verification.as_str() {
            "discouraged" => UserVerification::Discouraged,
            "preferred" => UserVerification::Preferred,
            "required" => {
                return Err(Error::Refused(
                    "this request requires user verification, which the software backend cannot provide"
                        .into(),
                ));
            }
            value => {
                return Err(Error::InvalidData(format!(
                    "unknown userVerification value {value:?}"
                )));
            }
        };
        Ok(Self {
            challenge,
            rp_id,
            origin,
            user_verification,
            allowed_credential_ids,
        })
    }

    fn candidates<'a>(&self, vault: &'a VaultState) -> Result<Vec<&'a PasskeyCredential>> {
        let mut candidates = Vec::new();
        for passkey in &vault.passkeys {
            if passkey.rp_id != self.rp_id {
                continue;
            }
            let credential_id = canonical_base64url(
                &passkey.credential_id,
                "stored credential ID",
                1,
                MAX_CREDENTIAL_ID_BYTES,
            )?;
            if self.allowed_credential_ids.is_empty()
                || self.allowed_credential_ids.contains(&credential_id)
            {
                candidates.push(passkey);
            }
        }
        if candidates.len() > MAX_CANDIDATES {
            return Err(Error::Refused(format!(
                "more than {MAX_CANDIDATES} local passkeys match this request"
            )));
        }
        candidates.sort_by(|a, b| {
            b.modified_at
                .total_cmp(&a.modified_at)
                .then_with(|| a.username.cmp(&b.username))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(candidates)
    }
}

fn canonical_base64url(value: &str, field: &str, min: usize, max: usize) -> Result<String> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|_| Error::InvalidData(format!("WebAuthn {field} is not base64url")))?;
    if !(min..=max).contains(&decoded.len()) {
        return Err(Error::InvalidData(format!(
            "WebAuthn {field} has an invalid length"
        )));
    }
    Ok(URL_SAFE_NO_PAD.encode(decoded))
}

fn default_user_verification() -> String {
    "preferred".into()
}

fn error_reply(error: &Error) -> serde_json::Value {
    let name = match error {
        Error::Refused(_) | Error::AuthenticationRequired(_) | Error::Config(_) => {
            "NotAllowedError"
        }
        Error::Security(_) => "SecurityError",
        Error::InvalidData(_) | Error::Json(_) | Error::Plist(_) | Error::Url(_) => "DataError",
        Error::Apple(_) | Error::Network(_) | Error::Io { .. } => "UnknownError",
    };
    serde_json::to_value(HostReply {
        ok: false,
        result: None,
        error: Some(HostError {
            name,
            message: error.to_string(),
        }),
    })
    .unwrap_or_else(|_| fallback_serialization_error())
}

fn fallback_serialization_error() -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "error": {
            "name": "UnknownError",
            "message": "native host could not serialize its reply"
        }
    })
}

#[cfg(test)]
mod tests {
    use p256::SecretKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use serde_json::json;

    use super::*;
    use crate::model::VaultState;
    use crate::paths::AppPaths;
    use crate::security::{KeyUsage, SoftwareFileBackend};

    #[test]
    fn extension_and_installer_use_the_native_host_name() {
        let service_worker = include_str!("../browser/chromium/service-worker.js");
        let installer = include_str!("../browser/chromium/install-host.sh");
        assert!(service_worker.contains(NATIVE_HOST_NAME));
        assert!(installer.contains(NATIVE_HOST_NAME));
    }

    struct Fixture {
        _root: tempfile::TempDir,
        backend: SoftwareFileBackend,
        paths: AppPaths,
        passkey_id: String,
        credential_id: String,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
            let paths =
                AppPaths::for_test(root.path()).unwrap_or_else(|error| panic!("paths: {error}"));
            let backend = SoftwareFileBackend::new(paths.clone());
            let secret = SecretKey::from_slice(&[9_u8; 32])
                .unwrap_or_else(|error| panic!("secret: {error}"));
            let mut x963 = secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            x963.extend_from_slice(&secret.to_bytes());
            let signing_key = backend
                .import_p256_x963(KeyUsage::WebAuthnSigning, &x963)
                .unwrap_or_else(|error| panic!("import: {error}"));
            let credential_id = URL_SAFE_NO_PAD.encode([1_u8, 2, 3, 4]);
            let passkey_id = "passkey-record".to_owned();
            let vault = VaultState {
                schema_version: 1,
                synced_at: 1,
                credentials: Vec::new(),
                passkeys: vec![PasskeyCredential {
                    id: passkey_id.clone(),
                    rp_id: "webauthn.io".into(),
                    credential_id: credential_id.clone(),
                    user_handle: URL_SAFE_NO_PAD.encode(b"alice"),
                    username: "alice@example.com".into(),
                    display_name: "Alice".into(),
                    created_at: 1.0,
                    modified_at: 2.0,
                    signing_key,
                }],
            };
            StateStore::new(&paths, &backend)
                .save_vault(&vault)
                .unwrap_or_else(|error| panic!("save vault: {error}"));
            Self {
                _root: root,
                backend,
                paths,
                passkey_id,
                credential_id,
            }
        }

        fn details(&self) -> String {
            json!({
                "challenge": URL_SAFE_NO_PAD.encode([7_u8; 32]),
                "rpId": "webauthn.io",
                "allowCredentials": [{"type": "public-key", "id": self.credential_id}],
                "userVerification": "preferred",
                "extensions": {
                    "remoteDesktopClientOverride": {
                        "origin": "https://webauthn.io",
                        "sameOriginWithAncestors": true
                    }
                }
            })
            .to_string()
        }

        fn send(&self, request: serde_json::Value) -> serde_json::Value {
            let store = StateStore::new(&self.paths, &self.backend);
            reply_for_message(request.to_string().as_bytes(), &self.backend, &store)
        }
    }

    #[test]
    fn inspection_returns_only_safe_candidate_metadata() {
        let fixture = Fixture::new();
        let reply = fixture.send(json!({
            "version": 1,
            "action": "inspect",
            "requestDetailsJson": fixture.details()
        }));
        assert_eq!(
            reply.get("ok").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(reply["result"]["rpId"], "webauthn.io");
        assert_eq!(reply["result"]["origin"], "https://webauthn.io");
        assert_eq!(reply["result"]["candidates"][0]["id"], fixture.passkey_id);
        let encoded = reply.to_string();
        assert!(!encoded.contains(&fixture.credential_id));
        assert!(!encoded.contains("YWxpY2U"));
    }

    #[test]
    fn approved_assertion_has_chromium_proxy_shape() {
        let fixture = Fixture::new();
        let reply = fixture.send(json!({
            "version": 1,
            "action": "assert",
            "requestDetailsJson": fixture.details(),
            "passkeyId": fixture.passkey_id
        }));
        assert_eq!(
            reply.get("ok").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        let response_json = reply["result"]["responseJson"]
            .as_str()
            .unwrap_or_else(|| panic!("response JSON"));
        let response: serde_json::Value = serde_json::from_str(response_json)
            .unwrap_or_else(|error| panic!("assertion JSON: {error}"));
        assert_eq!(response["authenticatorAttachment"], "platform");
        assert_eq!(response["type"], "public-key");
        assert_eq!(response["rawId"], fixture.credential_id);
        assert!(response["response"]["clientDataJSON"].is_string());
    }

    #[test]
    fn missing_or_cross_origin_browser_override_is_rejected() {
        let fixture = Fixture::new();
        let mut details: serde_json::Value = serde_json::from_str(&fixture.details())
            .unwrap_or_else(|error| panic!("details: {error}"));
        details["extensions"] = json!({});
        let missing = fixture.send(json!({
            "version": 1,
            "action": "inspect",
            "requestDetailsJson": details.to_string()
        }));
        assert_eq!(missing["error"]["name"], "SecurityError");

        let mut details: serde_json::Value = serde_json::from_str(&fixture.details())
            .unwrap_or_else(|error| panic!("details: {error}"));
        details["extensions"]["remoteDesktopClientOverride"]["sameOriginWithAncestors"] =
            json!(false);
        let cross_origin = fixture.send(json!({
            "version": 1,
            "action": "inspect",
            "requestDetailsJson": details.to_string()
        }));
        assert_eq!(cross_origin["error"]["name"], "SecurityError");
    }

    #[test]
    fn required_uv_and_unrequested_credentials_are_rejected() {
        let fixture = Fixture::new();
        let mut details: serde_json::Value = serde_json::from_str(&fixture.details())
            .unwrap_or_else(|error| panic!("details: {error}"));
        details["userVerification"] = json!("required");
        let required = fixture.send(json!({
            "version": 1,
            "action": "inspect",
            "requestDetailsJson": details.to_string()
        }));
        assert_eq!(required["error"]["name"], "NotAllowedError");

        let mut details: serde_json::Value = serde_json::from_str(&fixture.details())
            .unwrap_or_else(|error| panic!("details: {error}"));
        details["allowCredentials"][0]["id"] = URL_SAFE_NO_PAD.encode([8_u8; 32]).into();
        let no_match = fixture.send(json!({
            "version": 1,
            "action": "inspect",
            "requestDetailsJson": details.to_string()
        }));
        assert_eq!(no_match["error"]["name"], "NotAllowedError");
    }
}
