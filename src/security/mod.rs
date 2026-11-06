pub mod authorization;
mod root;
pub mod sep;
mod software;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Result;

pub use root::{FileRootKeySource, RootKeySource};
pub use software::SoftwareFileBackend;

/// Shared selection path for all entry points. Unsupported protection fails closed.
pub fn backend_for_config(
    config: &crate::config::Config,
    paths: &crate::paths::AppPaths,
) -> Result<Box<dyn SecurityBackend>> {
    match config.security_backend.as_str() {
        "software-file" => Ok(Box::new(SoftwareFileBackend::new(paths.clone()))),
        name => Err(crate::Error::Config(format!(
            "security backend {name} is not available in this build"
        ))),
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KeyUsage {
    Signing,
    Agreement,
    WebAuthnSigning,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    #[default]
    P384,
    P256,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRef {
    pub backend_id: String,
    pub key_id: String,
    pub usage: KeyUsage,
    /// Absent in state written before passkey support; those keys were all P-384.
    #[serde(default)]
    pub algorithm: KeyAlgorithm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    KeyStore = 1,
    Account = 2,
    Device = 3,
    Octagon = 4,
    Vault = 5,
    ProtectionMigration = 6,
    TrustRepair = 7,
    SyncUpload = 8,
}

impl Purpose {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::KeyStore),
            2 => Ok(Self::Account),
            3 => Ok(Self::Device),
            4 => Ok(Self::Octagon),
            5 => Ok(Self::Vault),
            6 => Ok(Self::ProtectionMigration),
            7 => Ok(Self::TrustRepair),
            8 => Ok(Self::SyncUpload),
            _ => Err(crate::Error::InvalidData(format!(
                "unknown encrypted-state purpose {value}"
            ))),
        }
    }

    pub fn label(self) -> &'static [u8] {
        match self {
            Self::KeyStore => b"key-store",
            Self::Account => b"account",
            Self::Device => b"device",
            Self::Octagon => b"octagon",
            Self::Vault => b"vault",
            Self::ProtectionMigration => b"protection-migration",
            Self::TrustRepair => b"trust-repair",
            Self::SyncUpload => b"sync-upload",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub seal: bool,
    pub generate_p384: bool,
    pub import_p384: bool,
    pub sign_p384_sha256: bool,
    pub sign_p384_sha384: bool,
    pub ecdh_p384: bool,
    pub import_p256: bool,
    pub sign_p256_sha256: bool,
}

pub trait SecurityBackend: Send + Sync {
    fn backend_id(&self) -> &'static str;
    fn capabilities(&self) -> BackendCapabilities;
    fn protection_capabilities(&self) -> authorization::ProtectionCapabilities {
        authorization::ProtectionCapabilities::default()
    }
    /// Explicit selected-item migration. Return a recipient-encrypted request,
    /// never an exported scalar. Unsupported/non-exportable backends refuse.
    fn prepare_passkey_protection(
        &self,
        _credential: &crate::model::PasskeyCredential,
        _recipient: &crate::broker::registry::Recipient,
        _owner: u32,
        _expected_revision: u64,
    ) -> Result<crate::broker::registry::ProtectedImport> {
        Err(crate::Error::Refused(
            "this backend cannot migrate a synced passkey".into(),
        ))
    }
    fn sign_p256_authorized(
        &self,
        key: &KeyRef,
        message: &[u8],
        requirement: authorization::AuthorizationRequirement,
    ) -> Result<authorization::AuthorizedSignature> {
        authorization::software_sign(self, key, message, requirement)
    }
    fn seal(&self, purpose: Purpose, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn open(&self, purpose: Purpose, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn generate_p384(&self, usage: KeyUsage) -> Result<KeyRef>;
    fn import_p384_x963(&self, usage: KeyUsage, private_x963: &[u8]) -> Result<KeyRef>;
    fn import_p256_x963(&self, usage: KeyUsage, private_x963: &[u8]) -> Result<KeyRef>;
    fn public_x963(&self, key: &KeyRef) -> Result<Vec<u8>>;
    fn public_spki(&self, key: &KeyRef) -> Result<Vec<u8>>;
    fn sign_p384_sha256(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>>;
    fn sign_p384_sha384(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>>;
    fn sign_p256_sha256(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>>;
    fn ecdh_p384(&self, key: &KeyRef, peer_x963: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn destroy_key(&self, key: &KeyRef) -> Result<()>;
}
