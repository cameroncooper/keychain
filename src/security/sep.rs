//! Application contract for a maintained SEP provider. This is not a firmware ABI.
//! The provider owns, authenticates and disposes SCRD contexts internally.

pub mod envelope;
mod native;
pub use native::{NativeSepProvider, StoredSepKey};

use std::time::{Duration, Instant};

use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::authorization::{AuthorizedSignature, ProtectionCapabilities, SigningProtection};
use super::{KeyAlgorithm, KeyRef, KeyUsage};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    #[error("SEP device is busy")]
    Busy,
    #[error("SEP device access denied")]
    PermissionDenied,
    #[error("biometric authorization canceled")]
    Canceled,
    #[error("fingerprint verification was not accepted")]
    Mismatch,
    #[error("requested SEP policy is unsupported")]
    UnsupportedPolicy,
    #[error("SEP hardware is unavailable")]
    Unavailable,
    #[error("SEP key is unavailable")]
    KeyUnavailable,
    #[error("SEP operation expired")]
    Expired,
    #[error("SEP request was replayed")]
    Replay,
    #[error("SEP operation completion is unknown; do not retry automatically")]
    AmbiguousCompletion,
    #[error("invalid SEP provider response")]
    InvalidResponse,
}

/// An owned request: the provider must authorize and sign this digest in one
/// transaction, enforce the deadline and reject reused IDs. No reusable auth handle.
pub struct SignRequest {
    pub id: Uuid,
    pub key: KeyRef,
    pub digest_sha256: [u8; 32],
    pub deadline: Instant,
}

pub struct SignResponse {
    pub id: Uuid,
    pub signature_der: Vec<u8>,
    pub user_verified: bool,
}

pub trait SepProvider: Send + Sync {
    fn backend_id(&self) -> &'static str;
    fn capabilities(&self) -> ProtectionCapabilities;
    /// Includes biometric capture, cancellation and context cleanup on all exits.
    fn sign_digest(&self, request: SignRequest) -> Result<SignResponse, ProviderError>;
}

/// Hash message bytes once for SEP's prehashed operation, then independently
/// verify the returned signature using the durably stored expected public key.
pub fn sign_native(
    provider: &dyn SepProvider,
    key: &KeyRef,
    expected_public_sec1: &[u8],
    message: &[u8],
    timeout: Duration,
) -> Result<AuthorizedSignature, ProviderError> {
    let capabilities = provider.capabilities();
    if !capabilities.native_p256_signing || !capabilities.operation_bound_user_verification {
        return Err(ProviderError::UnsupportedPolicy);
    }
    if key.backend_id != provider.backend_id()
        || key.algorithm != KeyAlgorithm::P256
        || key.usage != KeyUsage::WebAuthnSigning
    {
        return Err(ProviderError::KeyUnavailable);
    }
    if timeout.is_zero() || timeout > Duration::from_secs(120) || message.len() > 1024 * 1024 {
        return Err(ProviderError::UnsupportedPolicy);
    }
    let public = VerifyingKey::from_sec1_bytes(expected_public_sec1)
        .map_err(|_| ProviderError::InvalidResponse)?;
    let digest: [u8; 32] = Sha256::digest(message).into();
    let id = Uuid::new_v4();
    let deadline = Instant::now() + timeout;
    let response = provider.sign_digest(SignRequest {
        id,
        key: key.clone(),
        digest_sha256: digest,
        deadline,
    })?;
    if Instant::now() >= deadline {
        return Err(ProviderError::Expired);
    }
    if response.id != id || !response.user_verified || response.signature_der.len() > 80 {
        return Err(ProviderError::InvalidResponse);
    }
    let signature =
        Signature::from_der(&response.signature_der).map_err(|_| ProviderError::InvalidResponse)?;
    public
        .verify_prehash(&digest, &signature)
        .map_err(|_| ProviderError::InvalidResponse)?;
    let outcome = AuthorizedSignature::new(
        response.signature_der,
        key,
        message,
        true,
        SigningProtection::SepNative,
    );
    // The result is only constructed after verification, never from browser JSON.
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::authorization::AuthorizationRequirement;
    use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
    use std::sync::Mutex;

    struct FakeProvider {
        key: SigningKey,
        failure: Option<ProviderError>,
        wrong_digest: bool,
        verified: bool,
        wrong_request_id: bool,
        supported: bool,
        seen: Mutex<Vec<Uuid>>,
    }

    impl SepProvider for FakeProvider {
        fn backend_id(&self) -> &'static str {
            "test-sep"
        }
        fn capabilities(&self) -> ProtectionCapabilities {
            ProtectionCapabilities {
                native_p256_signing: self.supported,
                operation_bound_user_verification: true,
                ..Default::default()
            }
        }
        fn sign_digest(&self, request: SignRequest) -> Result<SignResponse, ProviderError> {
            if request.deadline <= Instant::now() {
                return Err(ProviderError::Expired);
            }
            let mut seen = self.seen.lock().map_err(|_| ProviderError::Unavailable)?;
            if seen.contains(&request.id) {
                return Err(ProviderError::Replay);
            }
            seen.push(request.id);
            if let Some(error) = self.failure {
                return Err(error);
            }
            let digest = if self.wrong_digest {
                [0; 32]
            } else {
                request.digest_sha256
            };
            let signature: Signature = self
                .key
                .sign_prehash(&digest)
                .map_err(|_| ProviderError::InvalidResponse)?;
            Ok(SignResponse {
                id: if self.wrong_request_id {
                    Uuid::new_v4()
                } else {
                    request.id
                },
                signature_der: signature.to_der().as_bytes().to_vec(),
                user_verified: self.verified,
            })
        }
    }

    fn fixture() -> (FakeProvider, KeyRef) {
        let key = SigningKey::from_slice(&[7; 32]).unwrap_or_else(|e| panic!("test key: {e}"));
        (
            FakeProvider {
                key,
                failure: None,
                wrong_digest: false,
                verified: true,
                wrong_request_id: false,
                supported: true,
                seen: Mutex::new(Vec::new()),
            },
            KeyRef {
                backend_id: "test-sep".into(),
                key_id: "test-key".into(),
                algorithm: KeyAlgorithm::P256,
                usage: KeyUsage::WebAuthnSigning,
            },
        )
    }

    #[test]
    fn native_signing_verifies_the_exact_message_without_double_hashing() {
        let (mut provider, key) = fixture();
        let public = provider.key.verifying_key().to_encoded_point(false);
        let outcome = sign_native(
            &provider,
            &key,
            public.as_bytes(),
            b"exact assertion",
            Duration::from_secs(10),
        )
        .unwrap_or_else(|e| panic!("sign: {e}"));
        assert_eq!(outcome.protection(), SigningProtection::SepNative);
        assert!(
            outcome
                .into_signature(
                    &key,
                    b"exact assertion",
                    AuthorizationRequirement::UserVerification
                )
                .is_ok()
        );
        provider.wrong_digest = true;
        assert!(matches!(
            sign_native(
                &provider,
                &key,
                public.as_bytes(),
                b"exact assertion",
                Duration::from_secs(10)
            ),
            Err(ProviderError::InvalidResponse)
        ));
    }

    #[test]
    fn cancellation_mismatch_and_uncertain_completion_are_preserved() {
        let (mut provider, key) = fixture();
        let public = provider.key.verifying_key().to_encoded_point(false);
        for error in [
            ProviderError::Canceled,
            ProviderError::Mismatch,
            ProviderError::AmbiguousCompletion,
        ] {
            provider.failure = Some(error);
            assert!(
                matches!(sign_native(&provider, &key, public.as_bytes(), b"assertion", Duration::from_secs(10)), Err(actual) if actual == error)
            );
        }
    }

    #[test]
    fn rejects_invalid_outcomes_even_when_the_signature_is_correct() {
        let (mut provider, key) = fixture();
        let public = provider.key.verifying_key().to_encoded_point(false);
        provider.verified = false;
        assert!(matches!(
            sign_native(
                &provider,
                &key,
                public.as_bytes(),
                b"assertion",
                Duration::from_secs(10)
            ),
            Err(ProviderError::InvalidResponse)
        ));
        provider.verified = true;
        provider.wrong_request_id = true;
        assert!(matches!(
            sign_native(
                &provider,
                &key,
                public.as_bytes(),
                b"assertion",
                Duration::from_secs(10)
            ),
            Err(ProviderError::InvalidResponse)
        ));
    }

    #[test]
    fn unsupported_policy_and_wrong_key_metadata_never_reach_the_provider() {
        let (mut provider, mut key) = fixture();
        let public = provider.key.verifying_key().to_encoded_point(false);
        provider.supported = false;
        assert!(matches!(
            sign_native(
                &provider,
                &key,
                public.as_bytes(),
                b"assertion",
                Duration::from_secs(10)
            ),
            Err(ProviderError::UnsupportedPolicy)
        ));
        provider.supported = true;
        key.backend_id = "other-backend".into();
        assert!(matches!(
            sign_native(
                &provider,
                &key,
                public.as_bytes(),
                b"assertion",
                Duration::from_secs(10)
            ),
            Err(ProviderError::KeyUnavailable)
        ));
        key.backend_id = "test-sep".into();
        key.usage = KeyUsage::Agreement;
        assert!(matches!(
            sign_native(
                &provider,
                &key,
                public.as_bytes(),
                b"assertion",
                Duration::from_secs(10)
            ),
            Err(ProviderError::KeyUnavailable)
        ));
        assert!(
            provider
                .seen
                .lock()
                .unwrap_or_else(|e| panic!("lock: {e}"))
                .is_empty()
        );
    }

    #[test]
    fn provider_rejects_replay_and_expired_requests() {
        let (provider, key) = fixture();
        let id = Uuid::new_v4();
        let request = || SignRequest {
            id,
            key: key.clone(),
            digest_sha256: [3; 32],
            deadline: Instant::now() + Duration::from_secs(10),
        };
        assert!(provider.sign_digest(request()).is_ok());
        assert!(matches!(
            provider.sign_digest(request()),
            Err(ProviderError::Replay)
        ));
        let mut expired = request();
        expired.deadline = Instant::now();
        assert!(matches!(
            provider.sign_digest(expired),
            Err(ProviderError::Expired)
        ));
    }
}
