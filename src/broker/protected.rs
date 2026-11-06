//! Selected synced-scalar operations. Plaintext stays in this privileged process;
//! the wire protocol accepts envelopes and returns assertions, never scalars.
use super::registry::{ProtectedRecord, item_binding};
use super::{Broker, Operation, session::ActiveSession};
use crate::security::authorization::{
    AuthorizationRequirement, AuthorizedSignature, SigningProtection,
};
use crate::security::sep::{ProviderError, envelope::item_view};
use crate::{Error, Result};
use keychain_sep_driver::memory::SecretBuffer;
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

impl Broker {
    pub(super) fn execute_protected(
        &self,
        id: Uuid,
        operation: Operation,
        canceled: Arc<AtomicBool>,
        session: ActiveSession,
    ) -> Result<serde_json::Value> {
        // Signing capability bit 2 does not advertise the decrypt extension.
        // Deployment must explicitly enable the matching local driver API.
        if !self.allow_item_decrypt {
            return Err(Error::Sep(ProviderError::UnsupportedPolicy));
        }
        let (record_id, details, verify) = match operation {
            Operation::SetSyncedInventory { records } => {
                self.registry.set_synced_inventory(self.owner, records)?;
                return Ok(serde_json::json!({"updated":true}));
            }
            Operation::RefreshProtectedMetadata {
                credential,
                public_sec1,
                revision,
            } => {
                self.registry.refresh_protected_metadata(
                    self.owner,
                    *credential,
                    &public_sec1,
                    revision,
                )?;
                return Ok(serde_json::json!({"updated":true}));
            }
            Operation::ProtectionState { record } => {
                return Ok(serde_json::to_value(
                    self.registry.protection_state(&record, self.owner)?,
                )?);
            }
            Operation::ItemRecipient => {
                return Ok(serde_json::to_value(self.registry.item_recipient()?)?);
            }
            Operation::ImportProtected { import } => {
                if import.diagnostic && !self.allow_diagnostics {
                    return Err(Error::Refused("diagnostic imports are disabled".into()));
                }
                if canceled.load(Ordering::Acquire) || !session.valid() {
                    return Err(Error::Sep(ProviderError::Canceled));
                }
                let revision = self.registry.import_protected(self.owner, *import)?;
                return Ok(serde_json::json!({"revision":revision, "verified":false}));
            }
            Operation::InspectProtected { record } => {
                let record = self.registry.verification_record(&record, self.owner)?;
                return Ok(serde_json::json!({"credential":record.credential,
                    "revision":record.revision,"verified":record.verified,
                    "diagnostic":record.diagnostic,"public_sec1":record.public_sec1}));
            }
            Operation::DiscardStaged { record, revision } => {
                self.registry
                    .discard_staged(&record, self.owner, revision)?;
                return Ok(serde_json::json!({"discarded":true}));
            }
            Operation::VerifyProtected { record } => (record, None, true),
            Operation::AssertProtected {
                record,
                request_details_json,
            } => (record, Some(request_details_json), false),
            _ => {
                return Err(Error::InvalidData(
                    "invalid protected-item operation".into(),
                ));
            }
        };
        let record = if verify {
            self.registry.verification_record(&record_id, self.owner)?
        } else {
            self.registry.load_protected(&record_id, self.owner)?
        };
        if record.diagnostic && !self.allow_diagnostics {
            return Err(Error::Refused("diagnostic operations are disabled".into()));
        }
        let context = if let Some(details) = details {
            if record.diagnostic
                || !record.verified
                || !self
                    .registry
                    .synced_record_enabled(&record_id, self.owner)?
            {
                return Err(Error::Refused(
                    "credential is not verified for browser use".into(),
                ));
            }
            let context = crate::browser::RequestContext::parse(&details)?;
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
            None
        };
        let action = if verify {
            format!("Verify protection for {}", record.credential.rp_id)
        } else {
            format!("Use your passkey for {}", record.credential.rp_id)
        };
        let authorization = self.native_authorization(
            crate::prompt::Presentation {
                id,
                application: "Keychain".into(),
                action,
                account: record.credential.username.clone(),
            },
            canceled,
            session,
            false,
        )?;
        let sign = |message: &[u8]| self.sign_protected_record(&record, message, &authorization);
        let result = if let Some(context) = context {
            let assertion = crate::passkey::assertion_for_origin_with(
                &record.credential,
                &context.challenge,
                &context.origin,
                AuthorizationRequirement::UserVerification,
                |key, message, _| {
                    if key != &record.credential.signing_key {
                        return Err(Error::Security("selected key changed".into()));
                    }
                    sign(message)
                },
            )?;
            serde_json::json!({"responseJson":serde_json::to_string(&assertion)?})
        } else {
            // Fixed, domain-separated verification message: no generic signing
            // oracle is available for a real imported credential.
            let message = format!(
                "cameroncooper.keychain/protection-check/v1/{}/{}/{id}",
                record.credential.id, record.revision
            );
            sign(message.as_bytes())?.into_signature(
                &record.credential.signing_key,
                message.as_bytes(),
                AuthorizationRequirement::UserVerification,
            )?;
            authorization.check()?;
            self.registry.commit_verified(&record)?;
            serde_json::json!({"revision":record.revision,"verified":true})
        };
        authorization.check()?;
        Ok(result)
    }
}

impl Broker {
    pub(super) fn sign_protected_record(
        &self,
        record: &ProtectedRecord,
        message: &[u8],
        authorization: &super::native::NativeAuthorization,
    ) -> Result<AuthorizedSignature> {
        if !self.allow_item_decrypt {
            return Err(ProviderError::UnsupportedPolicy.into());
        }
        authorization.check()?;
        let recipient = self.registry.item_key()?;
        if recipient.reference().key_id != record.recipient_id {
            return Err(Error::Security("selected recipient mismatch".into()));
        }
        let binding = item_binding(
            self.owner,
            record.revision,
            &record.recipient_id,
            &record.credential,
            &record.public_sec1,
        )?;
        // Memory protections must succeed before any plaintext arrives.
        let mut output =
            SecretBuffer::new().map_err(|e| Error::io("protected plaintext memory", e))?;
        let length = recipient.decrypt_selected(
            &self.device,
            &record.sealed,
            output.as_mut_array(),
            authorization.deadline,
            |guidance| authorization.progress(guidance),
        )?;
        authorization.check()?;
        let scalar = item_view(output.as_array(), length, &binding)?;
        let result = sign_scalar(record, scalar, message)?;
        drop(output);
        authorization.check()?;
        Ok(result)
    }
}

/// Called only after this transaction's successful biometric decrypt and binding
/// check. RustCrypto owns zeroize-on-drop key objects; compiler/library temporary
/// copies are not promised to be completely erased or individually mlocked.
fn sign_scalar(
    record: &ProtectedRecord,
    scalar: &[u8],
    message: &[u8],
) -> Result<AuthorizedSignature> {
    if scalar.len() != 32 || message.is_empty() || message.len() > 1024 * 1024 {
        return Err(Error::InvalidData(
            "invalid selected scalar or signing message bounds".into(),
        ));
    }
    let key = SigningKey::from_slice(scalar)
        .map_err(|_| Error::Security("invalid selected P-256 scalar".into()))?;
    let public = super::registry::decode_public(&record.public_sec1)?;
    let expected = VerifyingKey::from_sec1_bytes(&public)
        .map_err(|_| Error::Security("invalid selected public key".into()))?;
    if key.verifying_key() != &expected {
        return Err(Error::Security(
            "selected scalar does not match stored public key".into(),
        ));
    }
    let signature: Signature = key
        .try_sign(message)
        .map_err(|_| Error::Security("protected software signing failed".into()))?;
    drop(key);
    expected
        .verify(message, &signature)
        .map_err(|_| Error::Security("protected signature verification failed".into()))?;
    Ok(AuthorizedSignature::new(
        signature.to_der().as_bytes().to_vec(),
        &record.credential.signing_key,
        message,
        true,
        SigningProtection::SepProtectedSoftware,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PasskeyCredential, PasskeyProvenance};
    use crate::security::{KeyAlgorithm, KeyRef, KeyUsage};
    use base64::{
        Engine,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    fn record() -> ProtectedRecord {
        let key = p256::SecretKey::from_slice(&[9; 32]).unwrap_or_else(|e| panic!("key: {e}"));
        let id = Uuid::new_v4().to_string();
        ProtectedRecord {
            version: 1,
            owner: 1001,
            revision: 1,
            recipient_id: Uuid::new_v4().to_string(),
            public_sec1: STANDARD.encode(key.public_key().to_encoded_point(false).as_bytes()),
            sealed: vec![],
            diagnostic: true,
            verified: false,
            credential: PasskeyCredential {
                id: id.clone(),
                rp_id: "example.com".into(),
                provenance: PasskeyProvenance::Synced,
                credential_id: URL_SAFE_NO_PAD.encode([1; 16]),
                user_handle: URL_SAFE_NO_PAD.encode([2; 16]),
                username: "Synthetic".into(),
                display_name: "Synthetic".into(),
                created_at: 0.0,
                modified_at: 0.0,
                signing_key: KeyRef {
                    backend_id: "sep-protected-software-v1".into(),
                    key_id: id,
                    usage: KeyUsage::WebAuthnSigning,
                    algorithm: KeyAlgorithm::P256,
                },
            },
        }
    }
    #[test]
    fn decrypted_scalar_must_match_public_key_and_result_is_bound_to_message() {
        let record = record();
        let sign = || {
            sign_scalar(&record, &[9; 32], b"selected message")
                .unwrap_or_else(|e| panic!("sign: {e}"))
        };
        assert_eq!(sign().protection(), SigningProtection::SepProtectedSoftware);
        let signature = sign()
            .into_signature(
                &record.credential.signing_key,
                b"selected message",
                AuthorizationRequirement::UserVerification,
            )
            .unwrap_or_else(|e| panic!("signature: {e}"));
        let public = STANDARD
            .decode(&record.public_sec1)
            .unwrap_or_else(|e| panic!("public: {e}"));
        let verifier =
            VerifyingKey::from_sec1_bytes(&public).unwrap_or_else(|e| panic!("verifier: {e}"));
        verifier
            .verify(
                b"selected message",
                &Signature::from_der(&signature).unwrap_or_else(|e| panic!("DER: {e}")),
            )
            .unwrap_or_else(|e| panic!("verify: {e}"));
        assert!(
            sign()
                .into_signature(
                    &record.credential.signing_key,
                    b"different message",
                    AuthorizationRequirement::UserVerification
                )
                .is_err()
        );
        assert!(sign_scalar(&record, &[8; 32], b"selected message").is_err());
        assert!(sign_scalar(&record, &[0; 32], b"selected message").is_err());
        assert!(sign_scalar(&record, &[9; 31], b"selected message").is_err());
    }
    #[test]
    fn protected_synced_assertion_preserves_identity_and_backup_flags() {
        let record = record();
        let signed = crate::passkey::sign_assertion_with(
            &record.credential,
            &[4; 32],
            AuthorizationRequirement::UserVerification,
            |_, message, _| sign_scalar(&record, &[9; 32], message),
        )
        .unwrap_or_else(|e| panic!("assertion: {e}"));
        assert_eq!(signed.authenticator_data[32], 0x1d); // UP | UV | BE | BS
        let mut message = signed.authenticator_data;
        message.extend_from_slice(&[4; 32]);
        let public = STANDARD
            .decode(&record.public_sec1)
            .unwrap_or_else(|e| panic!("public: {e}"));
        VerifyingKey::from_sec1_bytes(&public)
            .unwrap_or_else(|e| panic!("verifier: {e}"))
            .verify(
                &message,
                &Signature::from_der(&signed.signature).unwrap_or_else(|e| panic!("DER: {e}")),
            )
            .unwrap_or_else(|e| panic!("verify: {e}"));
    }
}
