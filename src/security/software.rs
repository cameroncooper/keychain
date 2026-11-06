use std::collections::BTreeMap;
use std::fs;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use p256::SecretKey as P256SecretKey;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdh::diffie_hellman;
use p384::ecdsa::{
    Signature, SigningKey,
    signature::{Signer, hazmat::PrehashSigner},
};
use p384::elliptic_curve::rand_core::{OsRng, RngCore};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::pkcs8::EncodePublicKey;
use p384::{EncodedPoint, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{BackendCapabilities, KeyAlgorithm, KeyRef, KeyUsage, Purpose, SecurityBackend};
use super::{FileRootKeySource, RootKeySource};
use crate::paths::{AppPaths, atomic_write_private, read_bounded};
use crate::{Error, Result};

const BACKEND_ID: &str = "software-file-v1";
const MAGIC: &[u8; 4] = b"KCHN";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const HEADER_FIXED: usize = 4 + 1 + 1 + 1 + NONCE_LEN;

#[derive(Serialize, Deserialize)]
struct KeyRecord {
    usage: KeyUsage,
    /// Absent in key databases written before passkey support; those keys were all P-384.
    #[serde(default)]
    algorithm: KeyAlgorithm,
    scalar_b64: String,
}

impl Drop for KeyRecord {
    fn drop(&mut self) {
        self.scalar_b64.zeroize();
    }
}

#[derive(Default, Serialize, Deserialize)]
struct KeyDatabase {
    schema_version: u32,
    keys: BTreeMap<String, KeyRecord>,
}

pub struct SoftwareFileBackend {
    paths: AppPaths,
    keys_lock: Mutex<()>,
    root_source: Box<dyn RootKeySource>,
}

impl SoftwareFileBackend {
    pub fn new(paths: AppPaths) -> Self {
        let root_source = Box::new(FileRootKeySource::new(paths.clone()));
        Self::with_root_source(paths, root_source)
    }

    pub fn with_root_source(paths: AppPaths, root_source: Box<dyn RootKeySource>) -> Self {
        Self {
            paths,
            keys_lock: Mutex::new(()),
            root_source,
        }
    }

    fn root_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.root_source.root_key()
    }

    fn purpose_key(&self, purpose: Purpose) -> Result<Zeroizing<[u8; 32]>> {
        let root = self.root_key()?;
        let hkdf = Hkdf::<Sha384>::new(Some(b"keychain/local-state/v1"), root.as_slice());
        let mut out = Zeroizing::new([0_u8; 32]);
        hkdf.expand(purpose.label(), &mut *out)
            .map_err(|_| Error::Security("HKDF expansion failed".into()))?;
        Ok(out)
    }

    fn parse_envelope<'a>(
        &self,
        expected: Purpose,
        data: &'a [u8],
    ) -> Result<(&'a [u8], &'a [u8], &'a [u8])> {
        if data.len() < HEADER_FIXED || &data[..4] != MAGIC {
            return Err(Error::InvalidData(
                "not a keychain encrypted envelope".into(),
            ));
        }
        if data[4] != VERSION {
            return Err(Error::InvalidData(format!(
                "unsupported envelope version {}",
                data[4]
            )));
        }
        let purpose = Purpose::from_u8(data[5])?;
        if purpose != expected {
            return Err(Error::Security(format!(
                "encrypted {:?} data cannot be opened as {:?}",
                purpose, expected
            )));
        }
        let backend_len = usize::from(data[6]);
        let header_len = HEADER_FIXED
            .checked_add(backend_len)
            .ok_or_else(|| Error::InvalidData("envelope header overflow".into()))?;
        if data.len() < header_len + 16 {
            return Err(Error::InvalidData("truncated encrypted envelope".into()));
        }
        let nonce = &data[7..7 + NONCE_LEN];
        let backend = &data[HEADER_FIXED..header_len];
        if backend != BACKEND_ID.as_bytes() {
            return Err(Error::Security(format!(
                "state belongs to unsupported backend {}",
                String::from_utf8_lossy(backend)
            )));
        }
        Ok((&data[..header_len], nonce, &data[header_len..]))
    }

    fn load_keys(&self) -> Result<KeyDatabase> {
        let path = self.paths.keys_file();
        if !path.exists() {
            return Ok(KeyDatabase {
                schema_version: 1,
                keys: BTreeMap::new(),
            });
        }
        let envelope = read_bounded(&path)?;
        let plain = self.open(Purpose::KeyStore, &envelope)?;
        let db: KeyDatabase = serde_json::from_slice(&plain)?;
        if db.schema_version != 1 {
            return Err(Error::InvalidData(format!(
                "unsupported key database version {}",
                db.schema_version
            )));
        }
        Ok(db)
    }

    fn save_keys(&self, db: &KeyDatabase) -> Result<()> {
        let mut plain = Zeroizing::new(serde_json::to_vec(db)?);
        let envelope = self.seal(Purpose::KeyStore, &plain)?;
        plain.zeroize();
        atomic_write_private(&self.paths.keys_file(), &envelope)
    }

    fn key_secret_p384(&self, key: &KeyRef, usage: Option<KeyUsage>) -> Result<SecretKey> {
        if key.backend_id != BACKEND_ID {
            return Err(Error::Security(format!(
                "key {} belongs to backend {}",
                key.key_id, key.backend_id
            )));
        }
        if let Some(expected) = usage {
            if key.usage != expected {
                return Err(Error::Security("key usage mismatch".into()));
            }
        }
        if key.algorithm != KeyAlgorithm::P384 {
            return Err(Error::Security("key algorithm mismatch".into()));
        }
        let _guard = self
            .keys_lock
            .lock()
            .map_err(|_| Error::Security("software key database lock poisoned".into()))?;
        let db = self.load_keys()?;
        let record = db
            .keys
            .get(&key.key_id)
            .ok_or_else(|| Error::Security(format!("key {} does not exist", key.key_id)))?;
        if record.usage != key.usage || record.algorithm != key.algorithm {
            return Err(Error::Security("stored key metadata mismatch".into()));
        }
        let mut scalar = Zeroizing::new(
            B64.decode(&record.scalar_b64)
                .map_err(|_| Error::InvalidData("invalid software key encoding".into()))?,
        );
        let secret = SecretKey::from_slice(&scalar)
            .map_err(|_| Error::InvalidData("invalid P-384 private scalar".into()))?;
        scalar.zeroize();
        Ok(secret)
    }

    fn key_secret_p256(&self, key: &KeyRef, usage: Option<KeyUsage>) -> Result<P256SecretKey> {
        if key.backend_id != BACKEND_ID {
            return Err(Error::Security(format!(
                "key {} belongs to backend {}",
                key.key_id, key.backend_id
            )));
        }
        if let Some(expected) = usage {
            if key.usage != expected {
                return Err(Error::Security("key usage mismatch".into()));
            }
        }
        if key.algorithm != KeyAlgorithm::P256 {
            return Err(Error::Security("key algorithm mismatch".into()));
        }
        let _guard = self
            .keys_lock
            .lock()
            .map_err(|_| Error::Security("software key database lock poisoned".into()))?;
        let db = self.load_keys()?;
        let record = db
            .keys
            .get(&key.key_id)
            .ok_or_else(|| Error::Security(format!("key {} does not exist", key.key_id)))?;
        if record.usage != key.usage || record.algorithm != key.algorithm {
            return Err(Error::Security("stored key metadata mismatch".into()));
        }
        let mut scalar = Zeroizing::new(
            B64.decode(&record.scalar_b64)
                .map_err(|_| Error::InvalidData("invalid software key encoding".into()))?,
        );
        let secret = P256SecretKey::from_slice(&scalar)
            .map_err(|_| Error::InvalidData("invalid P-256 private scalar".into()))?;
        scalar.zeroize();
        Ok(secret)
    }

    fn insert_p384_secret(
        &self,
        usage: KeyUsage,
        secret: &SecretKey,
        reuse: bool,
    ) -> Result<KeyRef> {
        let _guard = self
            .keys_lock
            .lock()
            .map_err(|_| Error::Security("software key database lock poisoned".into()))?;
        let mut db = self.load_keys()?;
        // Imports are restart-safe: reuse an identical P-384 key/usage after a
        // metadata checkpoint failure. Generated keys remain fresh scalars.
        let scalar = Zeroizing::new(secret.to_bytes());
        let encoded = Zeroizing::new(B64.encode(scalar.as_slice()));
        if let Some((id, _)) = db.keys.iter().find(|(_, record)| {
            reuse
                && record.usage == usage
                && record.algorithm == KeyAlgorithm::P384
                && record.scalar_b64 == *encoded
        }) {
            return Ok(KeyRef {
                backend_id: BACKEND_ID.into(),
                key_id: id.clone(),
                usage,
                algorithm: KeyAlgorithm::P384,
            });
        }
        let key_id = Uuid::new_v4().to_string();
        db.keys.insert(
            key_id.clone(),
            KeyRecord {
                usage,
                algorithm: KeyAlgorithm::P384,
                scalar_b64: encoded.to_string(),
            },
        );
        self.save_keys(&db)?;
        Ok(KeyRef {
            backend_id: BACKEND_ID.into(),
            key_id,
            usage,
            algorithm: KeyAlgorithm::P384,
        })
    }

    fn insert_p256_secret(&self, usage: KeyUsage, secret: &P256SecretKey) -> Result<KeyRef> {
        let _guard = self
            .keys_lock
            .lock()
            .map_err(|_| Error::Security("software key database lock poisoned".into()))?;
        let mut db = self.load_keys()?;
        let public = secret.public_key().to_encoded_point(false);
        let key_id = format!(
            "webauthn-p256-{}",
            hex::encode(Sha256::digest(public.as_bytes()))
        );
        let mut scalar = Zeroizing::new(secret.to_bytes().to_vec());
        if let Some(existing) = db.keys.get(&key_id) {
            let existing_scalar = B64
                .decode(&existing.scalar_b64)
                .map_err(|_| Error::InvalidData("invalid software key encoding".into()))?;
            if existing.usage != usage
                || existing.algorithm != KeyAlgorithm::P256
                || existing_scalar != scalar.as_slice()
            {
                return Err(Error::Security(
                    "a different key already uses the imported passkey identifier".into(),
                ));
            }
        } else {
            db.keys.insert(
                key_id.clone(),
                KeyRecord {
                    usage,
                    algorithm: KeyAlgorithm::P256,
                    scalar_b64: B64.encode(scalar.as_slice()),
                },
            );
            self.save_keys(&db)?;
        }
        scalar.zeroize();
        Ok(KeyRef {
            backend_id: BACKEND_ID.into(),
            key_id,
            usage,
            algorithm: KeyAlgorithm::P256,
        })
    }

    #[cfg(test)]
    pub(crate) fn export_private_x963_for_test(&self, key: &KeyRef) -> Result<Zeroizing<Vec<u8>>> {
        let secret = self.key_secret_p384(key, None)?;
        let mut out = Zeroizing::new(
            secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        );
        out.extend_from_slice(&secret.to_bytes());
        Ok(out)
    }
}

impl SecurityBackend for SoftwareFileBackend {
    fn prepare_account_bootstrap(
        &self,
        owner: u32,
        account: &crate::model::AccountState,
        device: &crate::model::DeviceIdentity,
        peer: &crate::model::OctagonState,
    ) -> Result<crate::broker::account::Bootstrap> {
        if peer.signing_key.usage != KeyUsage::Signing
            || peer.signing_key.algorithm != KeyAlgorithm::P384
        {
            return Err(Error::Security(
                "Octagon signing key policy mismatch".into(),
            ));
        }
        let signing = self.public_spki(&peer.signing_key)?;
        let secret = self.key_secret_p384(&peer.encryption_key, Some(KeyUsage::Agreement))?;
        let mut private = Zeroizing::new(
            secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        );
        let scalar = Zeroizing::new(secret.to_bytes());
        private.extend_from_slice(&scalar);
        crate::broker::account::Bootstrap::from_private(
            owner, account, device, peer, &signing, &private,
        )
    }
    fn prepare_passkey_protection(
        &self,
        credential: &crate::model::PasskeyCredential,
        recipient: &crate::broker::registry::Recipient,
        owner: u32,
        expected_revision: u64,
    ) -> Result<crate::broker::registry::ProtectedImport> {
        if credential.provenance != crate::model::PasskeyProvenance::Synced {
            return Err(Error::Refused(
                "device-bound keys cannot be migrated as synced scalars".into(),
            ));
        }
        let key = self.key_secret_p256(&credential.signing_key, Some(KeyUsage::WebAuthnSigning))?;
        let scalar = Zeroizing::new(key.to_bytes());
        drop(key);
        crate::broker::registry::ProtectedImport::seal_scalar(
            owner,
            recipient,
            expected_revision,
            credential.clone(),
            &scalar,
            false,
        )
    }
    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            seal: true,
            generate_p384: true,
            import_p384: true,
            sign_p384_sha256: true,
            sign_p384_sha384: true,
            ecdh_p384: true,
            import_p256: true,
            sign_p256_sha256: true,
        }
    }

    fn seal(&self, purpose: Purpose, plaintext: &[u8]) -> Result<Vec<u8>> {
        let backend = BACKEND_ID.as_bytes();
        let backend_len = u8::try_from(backend.len())
            .map_err(|_| Error::Security("backend identifier is too long".into()))?;
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut header = Vec::with_capacity(HEADER_FIXED + backend.len());
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.push(purpose as u8);
        header.push(backend_len);
        header.extend_from_slice(&nonce);
        header.extend_from_slice(backend);
        let key = self.purpose_key(purpose)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| Error::Security("invalid local encryption key".into()))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Security("local state encryption failed".into()))?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    fn open(&self, purpose: Purpose, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (header, nonce, ciphertext) = self.parse_envelope(purpose, envelope)?;
        let key = self.purpose_key(purpose)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| Error::Security("invalid local encryption key".into()))?;
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Security("local state authentication failed".into()))
    }

    fn generate_p384(&self, usage: KeyUsage) -> Result<KeyRef> {
        self.insert_p384_secret(usage, &SecretKey::random(&mut OsRng), false)
    }

    fn import_p384_x963(&self, usage: KeyUsage, private_x963: &[u8]) -> Result<KeyRef> {
        if private_x963.len() != 145 || private_x963.first() != Some(&4) {
            return Err(Error::InvalidData(
                "P-384 private X9.63 data must be 145 bytes".into(),
            ));
        }
        let secret = SecretKey::from_slice(&private_x963[97..])
            .map_err(|_| Error::InvalidData("invalid P-384 private scalar".into()))?;
        if secret.public_key().to_encoded_point(false).as_bytes() != &private_x963[..97] {
            return Err(Error::InvalidData(
                "P-384 private scalar does not match its public point".into(),
            ));
        }
        self.insert_p384_secret(usage, &secret, true)
    }

    fn import_p256_x963(&self, usage: KeyUsage, private_x963: &[u8]) -> Result<KeyRef> {
        if usage != KeyUsage::WebAuthnSigning {
            return Err(Error::Security(
                "P-256 imports are restricted to WebAuthn signing".into(),
            ));
        }
        if private_x963.len() != 97 || private_x963.first() != Some(&4) {
            return Err(Error::InvalidData(
                "P-256 private X9.63 data must be 97 bytes".into(),
            ));
        }
        let secret = P256SecretKey::from_slice(&private_x963[65..])
            .map_err(|_| Error::InvalidData("invalid P-256 private scalar".into()))?;
        if secret.public_key().to_encoded_point(false).as_bytes() != &private_x963[..65] {
            return Err(Error::InvalidData(
                "P-256 private scalar does not match its public point".into(),
            ));
        }
        self.insert_p256_secret(usage, &secret)
    }

    fn public_x963(&self, key: &KeyRef) -> Result<Vec<u8>> {
        match key.algorithm {
            KeyAlgorithm::P384 => Ok(self
                .key_secret_p384(key, None)?
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()),
            KeyAlgorithm::P256 => Ok(self
                .key_secret_p256(key, None)?
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()),
        }
    }

    fn public_spki(&self, key: &KeyRef) -> Result<Vec<u8>> {
        match key.algorithm {
            KeyAlgorithm::P384 => self
                .key_secret_p384(key, None)?
                .public_key()
                .to_public_key_der()
                .map(|doc| doc.as_bytes().to_vec())
                .map_err(|e| Error::Security(format!("could not encode P-384 SPKI: {e}"))),
            KeyAlgorithm::P256 => self
                .key_secret_p256(key, None)?
                .public_key()
                .to_public_key_der()
                .map(|doc| doc.as_bytes().to_vec())
                .map_err(|e| Error::Security(format!("could not encode P-256 SPKI: {e}"))),
        }
    }

    fn sign_p384_sha384(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>> {
        let secret = self.key_secret_p384(key, Some(KeyUsage::Signing))?;
        let signing = SigningKey::from(secret);
        let signature: Signature = signing.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn sign_p384_sha256(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>> {
        let secret = self.key_secret_p384(key, Some(KeyUsage::Signing))?;
        let signing = SigningKey::from(secret);
        let digest = Sha256::digest(message);
        let signature: Signature = signing
            .sign_prehash(&digest)
            .map_err(|e| Error::Security(format!("P-384/SHA-256 signing failed: {e}")))?;
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn sign_p256_sha256(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>> {
        let secret = self.key_secret_p256(key, Some(KeyUsage::WebAuthnSigning))?;
        let signing = P256SigningKey::from(secret);
        let signature: P256Signature = signing.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn ecdh_p384(&self, key: &KeyRef, peer_x963: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let secret = self.key_secret_p384(key, Some(KeyUsage::Agreement))?;
        let encoded = EncodedPoint::from_bytes(peer_x963)
            .map_err(|_| Error::InvalidData("invalid P-384 peer point".into()))?;
        let peer = PublicKey::from_sec1_bytes(encoded.as_bytes())
            .map_err(|_| Error::InvalidData("P-384 peer point is not on the curve".into()))?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
    }

    fn destroy_key(&self, key: &KeyRef) -> Result<()> {
        if key.backend_id != BACKEND_ID {
            return Err(Error::Security("key belongs to another backend".into()));
        }
        let _guard = self
            .keys_lock
            .lock()
            .map_err(|_| Error::Security("software key database lock poisoned".into()))?;
        let mut db = self.load_keys()?;
        db.keys.remove(&key.key_id);
        if db.keys.is_empty() {
            let path = self.paths.keys_file();
            if path.exists() {
                fs::remove_file(&path).map_err(|e| Error::io(path, e))?;
            }
            return Ok(());
        }
        self.save_keys(&db)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
    use p384::ecdsa::{
        Signature, VerifyingKey,
        signature::{Verifier, hazmat::PrehashVerifier},
    };
    use tempfile::tempdir;

    use super::*;

    fn backend() -> (tempfile::TempDir, SoftwareFileBackend) {
        let dir = tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let paths = AppPaths::for_test(dir.path()).unwrap_or_else(|e| panic!("paths: {e}"));
        (dir, SoftwareFileBackend::new(paths))
    }

    #[test]
    fn envelope_round_trip_and_purpose_binding() {
        let (_dir, backend) = backend();
        let blob = backend
            .seal(Purpose::Account, b"secret")
            .unwrap_or_else(|e| panic!("seal: {e}"));
        assert_eq!(
            backend
                .open(Purpose::Account, &blob)
                .unwrap_or_else(|e| panic!("open: {e}"))
                .as_slice(),
            b"secret"
        );
        assert!(backend.open(Purpose::Vault, &blob).is_err());
    }

    #[test]
    fn tampering_is_rejected() {
        let (_dir, backend) = backend();
        let mut blob = backend
            .seal(Purpose::Vault, b"secret")
            .unwrap_or_else(|e| panic!("seal: {e}"));
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(backend.open(Purpose::Vault, &blob).is_err());
    }

    #[test]
    fn software_p384_sign_and_ecdh() {
        let (_dir, backend) = backend();
        let signing = backend
            .generate_p384(KeyUsage::Signing)
            .unwrap_or_else(|e| panic!("generate: {e}"));
        let sig = backend
            .sign_p384_sha384(&signing, b"hello")
            .unwrap_or_else(|e| panic!("sign: {e}"));
        let public = backend
            .key_secret_p384(&signing, None)
            .unwrap_or_else(|e| panic!("key: {e}"));
        let verify = VerifyingKey::from(public.public_key());
        let sig = Signature::from_der(&sig).unwrap_or_else(|e| panic!("signature: {e}"));
        assert!(verify.verify(b"hello", &sig).is_ok());

        let sig = backend
            .sign_p384_sha256(&signing, b"TLK share")
            .unwrap_or_else(|e| panic!("SHA-256 sign: {e}"));
        let sig = Signature::from_der(&sig).unwrap_or_else(|e| panic!("signature: {e}"));
        assert!(
            verify
                .verify_prehash(&Sha256::digest(b"TLK share"), &sig)
                .is_ok()
        );

        let a = backend
            .generate_p384(KeyUsage::Agreement)
            .unwrap_or_else(|e| panic!("generate: {e}"));
        let b = backend
            .generate_p384(KeyUsage::Agreement)
            .unwrap_or_else(|e| panic!("generate: {e}"));
        let a_pub = backend
            .public_x963(&a)
            .unwrap_or_else(|e| panic!("pub: {e}"));
        let b_pub = backend
            .public_x963(&b)
            .unwrap_or_else(|e| panic!("pub: {e}"));
        assert_eq!(
            backend
                .ecdh_p384(&a, &b_pub)
                .unwrap_or_else(|e| panic!("ecdh: {e}")),
            backend
                .ecdh_p384(&b, &a_pub)
                .unwrap_or_else(|e| panic!("ecdh: {e}"))
        );
    }

    #[test]
    fn software_p256_import_is_idempotent_and_usage_bound() {
        let (_dir, backend) = backend();
        let secret = P256SecretKey::from_slice(&[9_u8; 32])
            .unwrap_or_else(|error| panic!("P-256 key: {error}"));
        let mut x963 = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        x963.extend_from_slice(&secret.to_bytes());
        let first = backend
            .import_p256_x963(KeyUsage::WebAuthnSigning, &x963)
            .unwrap_or_else(|error| panic!("first import: {error}"));
        let second = backend
            .import_p256_x963(KeyUsage::WebAuthnSigning, &x963)
            .unwrap_or_else(|error| panic!("second import: {error}"));
        assert_eq!(first, second);
        assert!(backend.import_p256_x963(KeyUsage::Signing, &x963).is_err());

        let signature = backend
            .sign_p256_sha256(&first, b"WebAuthn assertion")
            .unwrap_or_else(|error| panic!("sign: {error}"));
        let signature = P256Signature::from_der(&signature)
            .unwrap_or_else(|error| panic!("signature: {error}"));
        let verifying = P256VerifyingKey::from(secret.public_key());
        assert!(verifying.verify(b"WebAuthn assertion", &signature).is_ok());
    }

    #[test]
    fn root_and_key_database_are_owner_only() {
        let (_dir, backend) = backend();
        backend
            .generate_p384(KeyUsage::Signing)
            .unwrap_or_else(|error| panic!("generate: {error}"));
        for path in [backend.paths.software_key_file(), backend.paths.keys_file()] {
            let mode = fs::metadata(&path)
                .unwrap_or_else(|error| panic!("metadata: {error}"))
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{}", path.display());
        }
    }
}
