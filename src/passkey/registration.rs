//! Validated WebAuthn creation requests and device-bound registration encoding.
//! Storage selection and durable key creation belong to the broker. This module
//! neither generates keys nor writes to Apple, and accepts no UI-supplied UV flag.
//!
//! Wire formats: <https://www.w3.org/TR/webauthn-3/> and
//! <https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy>.

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::browser::canonical_base64url;
use crate::model::{PasskeyCredential, PasskeyProvenance};
use crate::security::KeyRef;
use crate::security::authorization::{
    AuthorizationRequirement, AuthorizedSignature, SigningProtection,
};
use crate::{Error, Result};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Options {
    rp: RelyingParty,
    user: User,
    challenge: String,
    pub_key_cred_params: Vec<Parameters>,
    #[serde(default)]
    exclude_credentials: Vec<Descriptor>,
    #[serde(default)]
    authenticator_selection: Selection,
    #[serde(default)]
    attestation: Option<String>,
    extensions: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct RelyingParty {
    id: Option<String>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    name: String,
    display_name: String,
}

#[derive(Deserialize)]
struct Parameters {
    #[serde(rename = "type")]
    kind: String,
    alg: i64,
}

#[derive(Deserialize)]
struct Descriptor {
    #[serde(rename = "type")]
    kind: String,
    id: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Selection {
    authenticator_attachment: Option<String>,
    resident_key: Option<String>,
    #[serde(rename = "requireResidentKey")]
    _require_resident_key: Option<bool>,
    user_verification: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Caller {
    origin: String,
    same_origin_with_ancestors: bool,
}

/// All fields are frozen after validation, including Chromium's injected origin.
/// Parse again at the privileged boundary; a browser inspection is not authority.
pub struct CreationContext {
    binding: String,
    rp_id: String,
    rp_name: String,
    origin: String,
    challenge: String,
    user_handle: String,
    username: String,
    display_name: String,
    excluded: BTreeSet<String>,
    credential_properties: bool,
}

impl CreationContext {
    pub fn parse(details: &str) -> Result<Self> {
        if details.len() > 256 * 1024 {
            return Err(invalid("creation request exceeds the 256-KiB limit"));
        }
        let mut options: Options = serde_json::from_str(details)?;
        let caller: Caller = serde_json::from_value(
            options
                .extensions
                .remove("remoteDesktopClientOverride")
                .ok_or_else(|| {
                    Error::Security(
                        "creation request is missing Chromium's caller-origin override".into(),
                    )
                })?,
        )?;
        if !caller.same_origin_with_ancestors {
            return Err(Error::Security(
                "cross-origin iframe registration is not supported".into(),
            ));
        }
        let credential_properties = match options.extensions.remove("credProps") {
            None | Some(serde_json::Value::Bool(false)) => false,
            Some(serde_json::Value::Bool(true)) => true,
            _ => return Err(invalid("credProps must be boolean")),
        };
        if !options.extensions.is_empty() {
            return Err(invalid("unsupported creation extensions"));
        }
        let origin_url = url::Url::parse(&caller.origin)?;
        let rp_id = match options.rp.id {
            Some(id) => id,
            None => origin_url
                .host_str()
                .ok_or_else(|| invalid("origin has no host"))?
                .into(),
        };
        let rp_id =
            super::normalize_rp_id(&rp_id).map_err(|_| invalid("invalid relying-party ID"))?;
        let origin = super::validate_origin_for_rp(&caller.origin, &rp_id)?;
        validate_text(&options.rp.name)?;
        validate_text(&options.user.name)?;
        validate_text(&options.user.display_name)?;
        let challenge = canonical_base64url(&options.challenge, "challenge", 16, 4096)?;
        let user_handle = canonical_base64url(&options.user.id, "user handle", 1, 64)?;
        if options.pub_key_cred_params.len() > 256 {
            return Err(invalid("too many credential algorithm parameters"));
        }
        if !options
            .pub_key_cred_params
            .iter()
            .any(|p| p.kind == "public-key" && p.alg == -7)
        {
            return Err(Error::Refused(
                "registration requires ES256 support from the relying party".into(),
            ));
        }
        match options
            .authenticator_selection
            .authenticator_attachment
            .as_deref()
        {
            None | Some("platform") => (),
            Some("cross-platform") => {
                return Err(Error::Refused("this is a platform authenticator".into()));
            }
            _ => return Err(invalid("unknown authenticator attachment")),
        }
        // All credentials are discoverable, satisfying every resident-key
        // preference and the legacy requireResidentKey=true requirement.
        match options.authenticator_selection.resident_key.as_deref() {
            None | Some("discouraged" | "preferred" | "required") => (),
            _ => return Err(invalid("unknown residentKey value")),
        }
        match options.authenticator_selection.user_verification.as_deref() {
            None | Some("discouraged" | "preferred" | "required") => (),
            _ => return Err(invalid("unknown userVerification value")),
        }
        match options.attestation.as_deref() {
            None | Some("none" | "indirect" | "direct") => (),
            Some("enterprise") => {
                return Err(Error::Refused(
                    "enterprise attestation is unavailable".into(),
                ));
            }
            _ => return Err(invalid("unknown attestation preference")),
        }
        if options.exclude_credentials.len() > 256 {
            return Err(invalid("excludeCredentials exceeds the 256-entry limit"));
        }
        let mut excluded = BTreeSet::new();
        for descriptor in options.exclude_credentials {
            if descriptor.kind != "public-key" {
                return Err(invalid(
                    "excludeCredentials contains a non-public-key credential",
                ));
            }
            excluded.insert(canonical_base64url(
                &descriptor.id,
                "excluded credential ID",
                1,
                4096,
            )?);
        }
        Ok(Self {
            binding: hex::encode(Sha256::digest(details.as_bytes())),
            rp_id,
            rp_name: options.rp.name,
            origin,
            challenge,
            user_handle,
            username: options.user.name,
            display_name: options.user.display_name,
            excluded,
            credential_properties,
        })
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    /// Exact frozen browser request, including the injected origin and challenge.
    pub(crate) fn binding(&self) -> &str {
        &self.binding
    }
    pub fn rp_name(&self) -> &str {
        &self.rp_name
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn user_handle(&self) -> &str {
        &self.user_handle
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn excludes(&self, credential: &PasskeyCredential) -> bool {
        credential.rp_id == self.rp_id && self.excluded.contains(&credential.credential_id)
    }

    /// Fresh, verified signing authorizes this exact registration. No signature
    /// or reusable authorization token is stored in the none-attestation reply.
    /// This deliberately makes no claim of Apple or hardware attestation.
    pub fn finish_device_registration(
        &self,
        credential: &PasskeyCredential,
        public_sec1: &[u8],
        signer: impl FnOnce(&KeyRef, &[u8], AuthorizationRequirement) -> Result<AuthorizedSignature>,
    ) -> Result<Registration> {
        if credential.provenance != PasskeyProvenance::DeviceBound
            || credential.rp_id != self.rp_id
            || credential.user_handle != self.user_handle
            || credential.username != self.username
            || credential.display_name != self.display_name
        {
            return Err(Error::Security(
                "registration metadata does not match the selected device-bound credential".into(),
            ));
        }
        let canonical_id =
            canonical_base64url(&credential.credential_id, "new credential ID", 1, 1023)?;
        if canonical_id != credential.credential_id || self.excludes(credential) {
            return Err(Error::Refused(
                "new credential ID is noncanonical or excluded".into(),
            ));
        }
        let credential_id = URL_SAFE_NO_PAD
            .decode(&canonical_id)
            .map_err(|_| invalid("credential ID"))?;
        let public = p256::PublicKey::from_sec1_bytes(public_sec1)
            .map_err(|_| invalid("invalid registration public key"))?;
        let point = public.to_encoded_point(false);
        let x = point
            .x()
            .ok_or_else(|| invalid("missing public x coordinate"))?;
        let y = point
            .y()
            .ok_or_else(|| invalid("missing public y coordinate"))?;
        let cose = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(x.to_vec())),
            (int(-3), Value::Bytes(y.to_vec())),
        ]);
        let mut auth_data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        auth_data.push(0x01 | 0x04 | 0x40); // UP, UV, AT; device-bound BE/BS are zero.
        auth_data.extend_from_slice(&0_u32.to_be_bytes());
        auth_data.extend_from_slice(&[0_u8; 16]); // none attestation AAGUID
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&credential_id);
        ciborium::ser::into_writer(&cose, &mut auth_data)
            .map_err(|_| invalid("COSE encoding failed"))?;
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type":"webauthn.create", "challenge":self.challenge,
            "origin":self.origin, "crossOrigin":false,
        }))?;
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let requirement = AuthorizationRequirement::UserVerification;
        let outcome = signer(&credential.signing_key, &signed, requirement)?;
        if outcome.protection() != SigningProtection::SepNative {
            return Err(Error::Security(
                "device-bound registration requires native SEP signing".into(),
            ));
        }
        let signature = outcome.into_signature(&credential.signing_key, &signed, requirement)?;
        let signature = Signature::from_der(&signature)
            .map_err(|_| invalid("invalid registration signature"))?;
        VerifyingKey::from(public)
            .verify(&signed, &signature)
            .map_err(|_| {
                Error::Security(
                    "registration signature does not match the credential public key".into(),
                )
            })?;
        let attestation = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (
                Value::Text("authData".into()),
                Value::Bytes(auth_data.clone()),
            ),
        ]);
        let mut attestation_bytes = Vec::new();
        ciborium::ser::into_writer(&attestation, &mut attestation_bytes)
            .map_err(|_| invalid("attestation encoding failed"))?;
        let public_der = public
            .to_public_key_der()
            .map_err(|_| invalid("public key encoding failed"))?;
        Ok(Registration {
            id: canonical_id.clone(),
            raw_id: canonical_id,
            credential_type: "public-key",
            authenticator_attachment: "platform",
            response: RegistrationResponse {
                client_data_json: URL_SAFE_NO_PAD.encode(client_data),
                attestation_object: URL_SAFE_NO_PAD.encode(attestation_bytes),
                authenticator_data: URL_SAFE_NO_PAD.encode(auth_data),
                public_key: URL_SAFE_NO_PAD.encode(public_der.as_bytes()),
                public_key_algorithm: -7,
                transports: ["internal"],
            },
            client_extension_results: if self.credential_properties {
                serde_json::json!({"credProps":{"rk":true}})
            } else {
                serde_json::json!({})
            },
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub credential_type: &'static str,
    pub authenticator_attachment: &'static str,
    pub response: RegistrationResponse,
    pub client_extension_results: serde_json::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    pub public_key: String,
    pub public_key_algorithm: i32,
    pub transports: [&'static str; 1],
}

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}
fn invalid(message: &str) -> Error {
    Error::InvalidData(format!("WebAuthn registration: {message}"))
}
fn validate_text(text: &str) -> Result<()> {
    if text.len() > 4096 || text.chars().any(char::is_control) {
        return Err(invalid(
            "metadata exceeds 4096 bytes or contains control characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{KeyAlgorithm, KeyUsage};
    use p256::ecdsa::{SigningKey, signature::Signer};
    use serde_json::json;

    fn options() -> serde_json::Value {
        json!({
            "rp":{"id":"webauthn.io","name":"WebAuthn"},
            "user":{"id":URL_SAFE_NO_PAD.encode(b"test-user"),"name":"testuser","displayName":"Test User"},
            "challenge":URL_SAFE_NO_PAD.encode([23_u8;32]),
            "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "authenticatorSelection":{"residentKey":"required","userVerification":"required"},
            "extensions":{"credProps":true,"remoteDesktopClientOverride":{
                "origin":"https://webauthn.io","sameOriginWithAncestors":true
            }}
        })
    }

    fn context() -> CreationContext {
        CreationContext::parse(&options().to_string()).unwrap_or_else(|e| panic!("parse: {e}"))
    }

    fn credential() -> PasskeyCredential {
        PasskeyCredential {
            provenance: PasskeyProvenance::DeviceBound,
            id: "local-record".into(),
            rp_id: "webauthn.io".into(),
            credential_id: URL_SAFE_NO_PAD.encode([42_u8; 32]),
            user_handle: URL_SAFE_NO_PAD.encode(b"test-user"),
            username: "testuser".into(),
            display_name: "Test User".into(),
            created_at: 0.0,
            modified_at: 0.0,
            signing_key: KeyRef {
                backend_id: "test-native".into(),
                key_id: "native-key".into(),
                usage: KeyUsage::WebAuthnSigning,
                algorithm: KeyAlgorithm::P256,
            },
        }
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 32]).unwrap_or_else(|e| panic!("key: {e}"))
    }

    fn sign(
        key: &SigningKey,
        reference: &KeyRef,
        message: &[u8],
        uv: bool,
        protection: SigningProtection,
    ) -> AuthorizedSignature {
        let signature: Signature = key.sign(message);
        AuthorizedSignature::new(
            signature.to_der().as_bytes().to_vec(),
            reference,
            message,
            uv,
            protection,
        )
    }

    #[test]
    fn creation_rejects_wrong_origin_unsupported_requirements_and_oversized_inputs() {
        let cases = [
            (
                "/extensions/remoteDesktopClientOverride/origin",
                json!("https://evil.example"),
            ),
            (
                "/extensions/remoteDesktopClientOverride/sameOriginWithAncestors",
                json!(false),
            ),
            ("/user/id", json!(URL_SAFE_NO_PAD.encode([0_u8; 65]))),
            ("/challenge", json!("AA")),
            (
                "/pubKeyCredParams",
                json!([{"type":"public-key","alg":-257}]),
            ),
            (
                "/authenticatorSelection/authenticatorAttachment",
                json!("cross-platform"),
            ),
            (
                "/authenticatorSelection/userVerification",
                json!("sometimes"),
            ),
            ("/authenticatorSelection/residentKey", json!("never")),
            ("/attestation", json!("enterprise")),
            ("/extensions/prf", json!({"eval":{}})),
            ("/extensions/credProps", json!("true")),
            ("/user/name", json!("bad\nname")),
            (
                "/excludeCredentials",
                json!([{"type":"public-key","id":"!"}]),
            ),
        ];
        for (pointer, value) in cases {
            let mut details = options();
            // Some test members are absent from the baseline options.
            let (parent, field) = pointer
                .rsplit_once('/')
                .unwrap_or_else(|| panic!("pointer"));
            details
                .pointer_mut(parent)
                .unwrap_or_else(|| panic!("parent: {parent}"))[field] = value;
            assert!(
                CreationContext::parse(&details.to_string()).is_err(),
                "accepted {pointer}"
            );
        }
        let mut details = options();
        details["extensions"]
            .as_object_mut()
            .unwrap_or_else(|| panic!("extensions"))
            .remove("remoteDesktopClientOverride");
        assert!(CreationContext::parse(&details.to_string()).is_err());
        assert!(CreationContext::parse(&" ".repeat(256 * 1024 + 1)).is_err());
        details = options();
        details["excludeCredentials"] = json!(vec![json!({"type":"public-key","id":"AQ"}); 257]);
        assert!(CreationContext::parse(&details.to_string()).is_err());
    }

    #[test]
    fn absent_rp_id_uses_caller_host_and_exclusions_remain_rp_scoped() {
        let mut details = options();
        details["rp"]
            .as_object_mut()
            .unwrap_or_else(|| panic!("rp"))
            .remove("id");
        details["excludeCredentials"] =
            json!([{"type":"public-key","id":credential().credential_id}]);
        let context =
            CreationContext::parse(&details.to_string()).unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(context.rp_id(), "webauthn.io");
        assert!(context.excludes(&credential()));
        let mut other = credential();
        other.rp_id = "other.example".into();
        assert!(!context.excludes(&other));
    }

    #[test]
    fn registration_encodes_rp_bound_discoverable_device_credential_and_public_key() {
        let key = signing_key(7);
        let public = key.verifying_key().to_encoded_point(false);
        let registration = context()
            .finish_device_registration(
                &credential(),
                public.as_bytes(),
                |reference, message, requirement| {
                    assert_eq!(requirement, AuthorizationRequirement::UserVerification);
                    assert_eq!(&message[..32], Sha256::digest(b"webauthn.io").as_slice());
                    assert_eq!(message[32], 0x45);
                    Ok(sign(
                        &key,
                        reference,
                        message,
                        true,
                        SigningProtection::SepNative,
                    ))
                },
            )
            .unwrap_or_else(|e| panic!("registration: {e}"));
        let client = URL_SAFE_NO_PAD
            .decode(registration.response.client_data_json)
            .unwrap_or_else(|e| panic!("client: {e}"));
        let client: serde_json::Value =
            serde_json::from_slice(&client).unwrap_or_else(|e| panic!("JSON: {e}"));
        assert_eq!(client["type"], "webauthn.create");
        assert_eq!(client["origin"], "https://webauthn.io");
        assert_eq!(client["challenge"], options()["challenge"]);
        assert_eq!(
            registration.client_extension_results,
            json!({"credProps":{"rk":true}})
        );
        let auth = URL_SAFE_NO_PAD
            .decode(registration.response.authenticator_data)
            .unwrap_or_else(|e| panic!("auth: {e}"));
        assert_eq!(&auth[33..53], &[0_u8; 20]);
        assert_eq!(u16::from_be_bytes([auth[53], auth[54]]), 32);
        assert_eq!(&auth[55..87], &[42_u8; 32]);
        let cose: Value =
            ciborium::de::from_reader(&auth[87..]).unwrap_or_else(|e| panic!("COSE: {e}"));
        let Value::Map(cose) = cose else {
            panic!("COSE map")
        };
        assert!(cose.contains(&(int(3), int(-7))));
        assert!(cose.contains(&(int(-2), Value::Bytes(public.as_bytes()[1..33].to_vec()))));
        assert!(cose.contains(&(int(-3), Value::Bytes(public.as_bytes()[33..].to_vec()))));
        let bytes = URL_SAFE_NO_PAD
            .decode(registration.response.attestation_object)
            .unwrap_or_else(|e| panic!("attestation: {e}"));
        let Value::Map(attestation) = ciborium::de::from_reader::<Value, _>(bytes.as_slice())
            .unwrap_or_else(|e| panic!("CBOR: {e}"))
        else {
            panic!("attestation map")
        };
        assert!(attestation.contains(&(Value::Text("fmt".into()), Value::Text("none".into()))));
        assert!(attestation.contains(&(Value::Text("attStmt".into()), Value::Map(vec![]))));
        assert!(attestation.contains(&(Value::Text("authData".into()), Value::Bytes(auth))));
        use p256::pkcs8::DecodePublicKey;
        let der = URL_SAFE_NO_PAD
            .decode(registration.response.public_key)
            .unwrap_or_else(|e| panic!("SPKI: {e}"));
        let decoded =
            p256::PublicKey::from_public_key_der(&der).unwrap_or_else(|e| panic!("public: {e}"));
        assert_eq!(decoded.to_encoded_point(false), public);
    }

    #[test]
    fn registration_requires_exact_identity_native_protection_fresh_uv_and_matching_signature() {
        let key = signing_key(7);
        let public = key.verifying_key().to_encoded_point(false);
        let ctx = context();
        for (uv, protection) in [
            (false, SigningProtection::SepNative),
            (true, SigningProtection::Software),
            (true, SigningProtection::SepProtectedSoftware),
        ] {
            assert!(
                ctx.finish_device_registration(
                    &credential(),
                    public.as_bytes(),
                    |reference, message, _| Ok(sign(&key, reference, message, uv, protection))
                )
                .is_err()
            );
        }
        assert!(
            ctx.finish_device_registration(
                &credential(),
                public.as_bytes(),
                |reference, message, _| Ok(sign(
                    &signing_key(9),
                    reference,
                    message,
                    true,
                    SigningProtection::SepNative
                ))
            )
            .is_err()
        );
        assert!(
            ctx.finish_device_registration(&credential(), public.as_bytes(), |reference, _, _| Ok(
                sign(
                    &key,
                    reference,
                    b"another operation",
                    true,
                    SigningProtection::SepNative
                )
            ))
            .is_err()
        );
        let mut other = credential();
        other.provenance = PasskeyProvenance::Synced;
        assert!(
            ctx.finish_device_registration(&other, public.as_bytes(), |_, _, _| panic!(
                "synced identity reached signer"
            ))
            .is_err()
        );
        other = credential();
        other.user_handle = URL_SAFE_NO_PAD.encode(b"another user");
        assert!(
            ctx.finish_device_registration(&other, public.as_bytes(), |_, _, _| panic!(
                "wrong user reached signer"
            ))
            .is_err()
        );
        assert!(
            ctx.finish_device_registration(&credential(), &[0; 65], |_, _, _| {
                panic!("invalid public key reached signer")
            })
            .is_err()
        );
        let mut details = options();
        details["excludeCredentials"] =
            json!([{"type":"public-key","id":credential().credential_id}]);
        let excluded = CreationContext::parse(&details.to_string())
            .unwrap_or_else(|e| panic!("excluded context: {e}"));
        assert!(
            excluded
                .finish_device_registration(&credential(), public.as_bytes(), |_, _, _| {
                    panic!("excluded credential reached signer")
                })
                .is_err()
        );
    }
}
