use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use base64::{Engine, engine::general_purpose::STANDARD};
use keychain_sep_driver::{Device, Error as DriverError, Guidance};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ProviderError, SepProvider, SignRequest, SignResponse};
use crate::paths::{create_private_exclusive, read_bounded};
use crate::security::authorization::ProtectionCapabilities;
use crate::security::{KeyAlgorithm, KeyRef, KeyUsage};
use crate::{Error, Result};

const BACKEND_ID: &str = "sep-native-v1";

/// Application container, not a driver wire format. Contains no private scalar.
/// Production policy records belong in the broker-owned registry.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSepKey {
    version: u32,
    reference: KeyRef,
    policy: String,
    wrapped_blob: String,
    public_sec1: String,
    #[serde(default)]
    allow_decrypt: bool,
}

impl StoredSepKey {
    /// Wait only for a refused open. Once CREATE starts, never retry it on
    /// an ambiguous result. No public credential identity has been delivered yet.
    pub fn create_selected(
        path: &Path,
        deadline: Instant,
        mut progress: impl FnMut(Guidance) -> bool,
    ) -> Result<Self> {
        let mut device = acquire_device(deadline, || Device::open(path), &mut progress)?;
        if !progress(Guidance::Preparing) {
            return Err(ProviderError::Canceled.into());
        }
        if Instant::now() >= deadline {
            return Err(ProviderError::Expired.into());
        }
        Self::create(&mut device)
    }

    pub fn create(device: &mut Device) -> Result<Self> {
        Self::create_for_policy(device, false)
    }

    pub fn create_for_policy(device: &mut Device, allow_decrypt: bool) -> Result<Self> {
        let key = device.create(allow_decrypt).map_err(driver_error)?;
        let stored = Self {
            version: 1,
            reference: KeyRef {
                backend_id: BACKEND_ID.into(),
                key_id: Uuid::new_v4().to_string(),
                usage: KeyUsage::WebAuthnSigning,
                algorithm: KeyAlgorithm::P256,
            },
            policy: "biometry-any".into(),
            wrapped_blob: STANDARD.encode(key.wrapped_blob),
            public_sec1: STANDARD.encode(key.public),
            allow_decrypt,
        };
        stored.validate()?;
        Ok(stored)
    }

    pub fn reference(&self) -> &KeyRef {
        &self.reference
    }

    /// Diagnostic/building-block API. Production callers must resolve the item
    /// and validate its trusted binding inside the broker before exposing results.
    pub fn decrypt_into(
        &self,
        device: &mut Device,
        sealed: &[u8],
        output: &mut [u8; 4096],
        timeout: std::time::Duration,
        progress: impl FnMut(Guidance) -> bool,
    ) -> Result<usize> {
        use zeroize::Zeroize;
        output.zeroize();
        self.validate_for_decrypt()?;
        device
            .decrypt_into(&self.blob()?, sealed, output, timeout, progress)
            .map_err(driver_error)
    }

    pub(crate) fn validate_for_decrypt(&self) -> Result<()> {
        self.validate()?;
        if !self.allow_decrypt {
            return Err(Error::Refused(
                "SEP key does not permit item decryption".into(),
            ));
        }
        Ok(())
    }

    /// Opens the key node before one blocking decrypt operation. Only a busy
    /// open is retried; a submitted command is never replayed.
    pub(crate) fn decrypt_selected(
        &self,
        path: &Path,
        sealed: &[u8],
        output: &mut [u8; 4096],
        deadline: Instant,
        mut progress: impl FnMut(Guidance) -> bool,
    ) -> Result<usize> {
        use zeroize::Zeroize;
        output.zeroize();
        self.validate()?;
        let mut device = acquire_device(deadline, || Device::open(path), &mut progress)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(ProviderError::Expired)?;
        self.decrypt_into(&mut device, sealed, output, remaining, progress)
    }

    pub fn public_sec1(&self) -> Result<Vec<u8>> {
        let public = STANDARD
            .decode(&self.public_sec1)
            .map_err(|_| Error::InvalidData("invalid SEP public key encoding".into()))?;
        if public.len() != 65
            || public.first() != Some(&4)
            || p256::PublicKey::from_sec1_bytes(&public).is_err()
        {
            return Err(Error::InvalidData("invalid SEP P-256 public key".into()));
        }
        Ok(public)
    }

    fn blob(&self) -> Result<Vec<u8>> {
        let blob = STANDARD
            .decode(&self.wrapped_blob)
            .map_err(|_| Error::InvalidData("invalid SEP wrapped key encoding".into()))?;
        if blob.is_empty() || blob.len() > keychain_sep_driver::MAX_BLOB {
            return Err(Error::InvalidData("invalid SEP wrapped key length".into()));
        }
        Ok(blob)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.policy != "biometry-any"
            || self.reference.backend_id != BACKEND_ID
            || self.reference.algorithm != KeyAlgorithm::P256
            || self.reference.usage != KeyUsage::WebAuthnSigning
            || Uuid::parse_str(&self.reference.key_id).is_err()
        {
            return Err(Error::InvalidData(
                "invalid SEP application key metadata".into(),
            ));
        }
        self.blob()?;
        self.public_sec1()?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).map_err(|e| Error::io(path, e))?;
        if metadata.len() > 16 * 1024 {
            return Err(Error::InvalidData("SEP key file too large".into()));
        }
        let data = read_bounded(path)?;
        if data.len() > 16 * 1024 {
            return Err(Error::InvalidData("SEP key file too large".into()));
        }
        let stored: Self = serde_json::from_slice(&data)?;
        stored.validate()?;
        Ok(stored)
    }

    pub fn save_new(&self, path: &Path) -> Result<()> {
        self.validate()?;
        create_private_exclusive(path, &serde_json::to_vec(self)?)
    }
}

pub struct NativeSepProvider {
    key: StoredSepKey,
    path: PathBuf,
    seen: Mutex<HashSet<Uuid>>,
    progress: Box<dyn Fn(Guidance) -> bool + Send + Sync>,
}

impl NativeSepProvider {
    pub fn new(
        key: StoredSepKey,
        device: PathBuf,
        progress: impl Fn(Guidance) -> bool + Send + Sync + 'static,
    ) -> Result<Self> {
        key.validate()?;
        Ok(Self {
            key,
            path: device,
            seen: Mutex::new(HashSet::new()),
            progress: Box::new(progress),
        })
    }
    pub fn reference(&self) -> &KeyRef {
        self.key.reference()
    }
    pub fn public_sec1(&self) -> Result<Vec<u8>> {
        self.key.public_sec1()
    }
}

impl SepProvider for NativeSepProvider {
    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }
    fn capabilities(&self) -> ProtectionCapabilities {
        // Implementation guarantees, not a claim the current boot has the device.
        // Device::open rechecks ABI/capability on each actual operation.
        ProtectionCapabilities {
            native_p256_signing: true,
            operation_bound_user_verification: true,
            fresh_biometric_per_operation: true,
            ..Default::default()
        }
    }
    fn sign_digest(
        &self,
        request: SignRequest,
    ) -> std::result::Result<SignResponse, ProviderError> {
        if request.key != self.key.reference {
            return Err(ProviderError::KeyUnavailable);
        }
        let remaining = request
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(ProviderError::Expired)?;
        if remaining < std::time::Duration::from_millis(1) {
            return Err(ProviderError::Expired);
        }
        {
            let mut seen = self.seen.lock().map_err(|_| ProviderError::Unavailable)?;
            if seen.contains(&request.id) {
                return Err(ProviderError::Replay);
            }
            if seen.len() >= 256 {
                return Err(ProviderError::Busy);
            }
            seen.insert(request.id);
        }
        let blob = self.key.blob().map_err(|_| ProviderError::KeyUnavailable)?;
        let mut device = acquire_device(
            request.deadline,
            || Device::open(&self.path),
            |guidance| (self.progress)(guidance),
        )?;
        let remaining = request
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(ProviderError::Expired)?
            .min(remaining);
        if remaining < std::time::Duration::from_millis(1) {
            return Err(ProviderError::Expired);
        }
        let signature_der = device
            .sign_digest(&blob, &request.digest_sha256, remaining, |guidance| {
                (self.progress)(guidance)
            })
            .map_err(map_driver)?;
        // Successful blocking completion includes biometric policy and credential disposal.
        // sign_native independently verifies the signature before exposing outcome.
        Ok(SignResponse {
            id: request.id,
            signature_der,
            user_verified: true,
        })
    }
}

fn acquire_device<T>(
    deadline: Instant,
    mut open: impl FnMut() -> std::result::Result<T, DriverError>,
    mut progress: impl FnMut(Guidance) -> bool,
) -> std::result::Result<T, ProviderError> {
    loop {
        if Instant::now() >= deadline {
            return Err(ProviderError::Expired);
        }
        match open() {
            Ok(device) => return Ok(device),
            Err(error) if matches!(&error, DriverError::Io(io) if io.raw_os_error() == Some(libc::EBUSY)) =>
            {
                // Retry ONLY a refused open which started no operation.
                if !progress(Guidance::WaitingForDevice) {
                    return Err(ProviderError::Canceled);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => {
                return Err(
                    if matches!(&error, DriverError::Io(io) if io.raw_os_error() == Some(libc::EACCES))
                    {
                        ProviderError::PermissionDenied
                    } else {
                        map_driver(error)
                    },
                );
            }
        }
    }
}

fn map_driver(error: DriverError) -> ProviderError {
    match error {
        DriverError::Canceled => ProviderError::Canceled,
        DriverError::Expired => ProviderError::Expired,
        DriverError::Unsupported | DriverError::InvalidInput => ProviderError::UnsupportedPolicy,
        DriverError::InvalidResponse => ProviderError::InvalidResponse,
        DriverError::Ambiguous(error) => uncertain_driver_error(&error),
        DriverError::Io(error) => match error.raw_os_error() {
            Some(libc::EBUSY) => ProviderError::Busy,
            Some(libc::EPERM) => ProviderError::PermissionDenied,
            Some(libc::EACCES) => ProviderError::Mismatch,
            Some(libc::ETIMEDOUT) => ProviderError::Expired,
            Some(libc::ECANCELED) => ProviderError::Canceled,
            Some(libc::ENOTTY | libc::EINVAL | libc::EOPNOTSUPP) => {
                ProviderError::UnsupportedPolicy
            }
            Some(libc::ENOENT | libc::ENODEV) => ProviderError::Unavailable,
            _ => uncertain_driver_error(&error),
        },
    }
}

fn uncertain_driver_error(error: &std::io::Error) -> ProviderError {
    // Numeric diagnostic only: never format driver payloads, key material or
    // free-form errors. The caller still treats completion as uncertain and
    // cannot turn this into an automatic capture retry.
    eprintln!(
        "SEP driver completion uncertain: errno={}",
        error.raw_os_error().unwrap_or(0)
    );
    ProviderError::AmbiguousCompletion
}

fn driver_error(error: DriverError) -> Error {
    Error::Sep(map_driver(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_wait_can_be_canceled_and_never_retries_ambiguous_operations() {
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let mut attempts = 0;
        let result: std::result::Result<(), _> = acquire_device(
            deadline,
            || {
                attempts += 1;
                Err(DriverError::Io(std::io::Error::from_raw_os_error(
                    libc::EBUSY,
                )))
            },
            |guidance| {
                assert_eq!(guidance, Guidance::WaitingForDevice);
                false
            },
        );
        assert!(matches!(result, Err(ProviderError::Canceled)));
        assert_eq!(attempts, 1);
        attempts = 0;
        let result: std::result::Result<(), _> = acquire_device(
            deadline,
            || {
                attempts += 1;
                Err(DriverError::Ambiguous(std::io::Error::from_raw_os_error(
                    libc::EIO,
                )))
            },
            |_| true,
        );
        assert!(matches!(result, Err(ProviderError::AmbiguousCompletion)));
        assert_eq!(attempts, 1);
    }
    #[test]
    fn device_becomes_available_without_restarting_other_clients() {
        let mut attempts = 0;
        let device = acquire_device(
            Instant::now() + std::time::Duration::from_secs(1),
            || {
                attempts += 1;
                if attempts == 1 {
                    Err(DriverError::Io(std::io::Error::from_raw_os_error(
                        libc::EBUSY,
                    )))
                } else {
                    Ok(42)
                }
            },
            |_| true,
        )
        .unwrap_or_else(|e| panic!("acquire: {e}"));
        assert_eq!(device, 42);
        assert_eq!(attempts, 2);
    }
}
