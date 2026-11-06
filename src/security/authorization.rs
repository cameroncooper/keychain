//! Authorization belongs to the operation that consumes it. These outcomes are
//! deliberately not deserializable from browser requests or reusable as grants.

use sha2::{Digest, Sha256};

use super::{KeyRef, SecurityBackend};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationRequirement {
    /// Presence was approved by the local interface; this does not establish UV.
    PresenceApproved,
    /// The backend must verify the user within this exact signing transaction.
    UserVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningProtection {
    Software,
    SepProtectedSoftware,
    SepNative,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProtectionCapabilities {
    pub biometric_root_unseal: bool,
    pub native_p256_signing: bool,
    pub imported_p256_signing: bool,
    pub operation_bound_user_verification: bool,
    pub fresh_biometric_per_operation: bool,
}

pub struct AuthorizedSignature {
    signature_der: Vec<u8>,
    key: KeyRef,
    message_digest: [u8; 32],
    user_verified: bool,
    protection: SigningProtection,
}

impl AuthorizedSignature {
    pub(crate) fn new(
        signature_der: Vec<u8>,
        key: &KeyRef,
        message: &[u8],
        user_verified: bool,
        protection: SigningProtection,
    ) -> Self {
        Self {
            signature_der,
            key: key.clone(),
            message_digest: Sha256::digest(message).into(),
            user_verified,
            protection,
        }
    }

    /// Consume the result for precisely the key, message and verification level
    /// requested. This is a result check, never an authorization token.
    pub fn into_signature(
        self,
        key: &KeyRef,
        message: &[u8],
        requirement: AuthorizationRequirement,
    ) -> Result<Vec<u8>> {
        if self.key != *key || self.message_digest != <[u8; 32]>::from(Sha256::digest(message)) {
            return Err(Error::Security(
                "signing outcome does not match the requested operation".into(),
            ));
        }
        if requirement == AuthorizationRequirement::UserVerification && !self.user_verified {
            return Err(Error::Refused(
                "signing operation did not verify the user".into(),
            ));
        }
        Ok(self.signature_der)
    }

    pub fn protection(&self) -> SigningProtection {
        self.protection
    }
}

pub(crate) fn software_sign(
    backend: &(impl SecurityBackend + ?Sized),
    key: &KeyRef,
    message: &[u8],
    requirement: AuthorizationRequirement,
) -> Result<AuthorizedSignature> {
    if requirement == AuthorizationRequirement::UserVerification {
        return Err(Error::Refused(
            "this backend cannot verify the user for a signing operation".into(),
        ));
    }
    let signature = backend.sign_p256_sha256(key, message)?;
    Ok(AuthorizedSignature::new(
        signature,
        key,
        message,
        false,
        SigningProtection::Software,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{KeyAlgorithm, KeyUsage};

    fn key() -> KeyRef {
        KeyRef {
            backend_id: "test".into(),
            key_id: "key".into(),
            usage: KeyUsage::WebAuthnSigning,
            algorithm: KeyAlgorithm::P256,
        }
    }

    #[test]
    fn result_cannot_be_rebound_to_another_key_or_message_or_verification_level() {
        let original = key();
        let result = || {
            AuthorizedSignature::new(
                vec![1],
                &original,
                b"approved",
                false,
                SigningProtection::Software,
            )
        };
        assert!(
            result()
                .into_signature(
                    &original,
                    b"other",
                    AuthorizationRequirement::PresenceApproved
                )
                .is_err()
        );
        let mut other = key();
        other.key_id = "other".into();
        assert!(
            result()
                .into_signature(
                    &other,
                    b"approved",
                    AuthorizationRequirement::PresenceApproved
                )
                .is_err()
        );
        assert!(
            result()
                .into_signature(
                    &original,
                    b"approved",
                    AuthorizationRequirement::UserVerification
                )
                .is_err()
        );
        assert!(
            result()
                .into_signature(
                    &original,
                    b"approved",
                    AuthorizationRequirement::PresenceApproved
                )
                .is_ok()
        );
    }
}
