mod software;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Result;

pub use software::SoftwareFileBackend;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KeyUsage {
    Signing,
    Agreement,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRef {
    pub backend_id: String,
    pub key_id: String,
    pub usage: KeyUsage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    KeyStore = 1,
    Account = 2,
    Device = 3,
    Octagon = 4,
    Vault = 5,
}

impl Purpose {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::KeyStore),
            2 => Ok(Self::Account),
            3 => Ok(Self::Device),
            4 => Ok(Self::Octagon),
            5 => Ok(Self::Vault),
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
}

pub trait SecurityBackend: Send + Sync {
    fn backend_id(&self) -> &'static str;
    fn capabilities(&self) -> BackendCapabilities;
    fn seal(&self, purpose: Purpose, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn open(&self, purpose: Purpose, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn generate_p384(&self, usage: KeyUsage) -> Result<KeyRef>;
    fn import_p384_x963(&self, usage: KeyUsage, private_x963: &[u8]) -> Result<KeyRef>;
    fn public_x963(&self, key: &KeyRef) -> Result<Vec<u8>>;
    fn public_spki(&self, key: &KeyRef) -> Result<Vec<u8>>;
    fn sign_p384_sha256(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>>;
    fn sign_p384_sha384(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>>;
    fn ecdh_p384(&self, key: &KeyRef, peer_x963: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn destroy_key(&self, key: &KeyRef) -> Result<()>;
}
