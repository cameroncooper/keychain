use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::model::{PasskeyCredential, PasskeyProvenance};
use crate::paths::{AppPaths, atomic_write_private, create_private_exclusive, read_bounded};
use crate::security::sep::StoredSepKey;
use crate::security::{Purpose, SecurityBackend, SoftwareFileBackend};
use crate::{Error, Result};
mod login;
pub use login::{LoginRecord, LoginState, LoginSummary};
mod protected;
mod registration;
mod removal;
pub use removal::LocalRemoval;
mod synced_registration;
#[cfg(test)]
pub(crate) mod test_support;
pub(super) use protected::decode_public;
pub use protected::{
    ProtectedImport, ProtectedRecord, ProtectedSummary, ProtectionState, Recipient, item_binding,
};
pub use synced_registration::SyncedCreation;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    pub owner: u32,
    pub diagnostic: bool,
    pub registered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    creation_binding: Option<String>,
    pub credential: PasskeyCredential,
    pub native_key: StoredSepKey,
}

pub struct Registry {
    pub(super) directory: PathBuf,
    pub(super) backend: SoftwareFileBackend,
}

/// Guard the directory that actually holds broker envelopes, including upload
/// journals. A long-lived broker must also refuse root regeneration if its root
/// is lost after startup, not only when Registry::open performs its first check.
struct RegistryRoot {
    directory: PathBuf,
    key_path: PathBuf,
    inner: crate::security::FileRootKeySource,
    initialized: std::sync::atomic::AtomicBool,
}
impl crate::security::RootKeySource for RegistryRoot {
    fn root_key(&self) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        use std::sync::atomic::Ordering;
        // Existing roots are read without invoking an auto-initializing source.
        // Unlink during an open read keeps that FD valid; unlink before open
        // fails closed once this registry has ever observed an initialized root.
        match read_bounded(&self.key_path) {
            Ok(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                let key: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Security("invalid broker metadata root length".into()))?;
                self.initialized.store(true, Ordering::Release);
                Ok(zeroize::Zeroizing::new(key))
            }
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                if self.initialized.load(Ordering::Acquire) {
                    return Err(Error::Security(
                        "initialized broker metadata root is missing; refusing replacement".into(),
                    ));
                }
                refuse_missing_root(&self.directory, &self.key_path)?;
                let key = self.inner.root_key()?;
                self.initialized.store(true, Ordering::Release);
                Ok(key)
            }
            Err(error) => Err(error),
        }
    }
}
fn refuse_missing_root(directory: &Path, key_path: &Path) -> Result<()> {
    if !key_path.try_exists().map_err(|e| Error::io(key_path, e))? {
        for entry in std::fs::read_dir(directory).map_err(|e| Error::io(directory, e))? {
            let entry = entry.map_err(|e| Error::io(directory, e))?;
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "enc")
            {
                return Err(Error::Security("broker metadata root is missing while encrypted records exist; refusing replacement".into()));
            }
        }
    }
    Ok(())
}
impl Registry {
    pub fn uploads(&self) -> Result<crate::apple::ckks::upload::UploadStore<'_>> {
        crate::apple::ckks::upload::UploadStore::new(&self.directory, &self.backend)
    }
    fn synced_inventory(&self, owner: u32) -> Result<Option<std::collections::BTreeSet<String>>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Inventory {
            version: u32,
            owner: u32,
            records: std::collections::BTreeSet<String>,
        }
        let path = self.directory.join("synced-inventory.enc");
        if !path.try_exists().map_err(|e| Error::io(&path, e))? {
            return Ok(None);
        }
        let data = read_bounded(&path)?;
        if data.len() > 256 * 1024 {
            return Err(Error::InvalidData("synced inventory exceeds limit".into()));
        }
        let plain = self.backend.open(Purpose::Vault, &data)?;
        let inventory: Inventory = serde_json::from_slice(&plain)?;
        if inventory.version != 1 || inventory.owner != owner || inventory.records.len() > 4096 {
            return Err(Error::Security(
                "synced inventory identity/policy mismatch".into(),
            ));
        }
        for id in &inventory.records {
            self.filename(id)?;
        }
        Ok(Some(inventory.records))
    }
    pub fn synced_record_enabled(&self, id: &str, owner: u32) -> Result<bool> {
        Ok(self
            .synced_inventory(owner)?
            .is_none_or(|records| records.contains(id)))
    }
    fn write_inventory(
        &self,
        owner: u32,
        records: &std::collections::BTreeSet<String>,
    ) -> Result<()> {
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(
            &serde_json::json!({"version":1,"owner":owner,"records":records}),
        )?);
        atomic_write_private(
            &self.directory.join("synced-inventory.enc"),
            &self.backend.seal(Purpose::Vault, &plain)?,
        )
    }
    pub fn set_synced_inventory(&self, owner: u32, records: Vec<String>) -> Result<()> {
        let _lock = self.update_lock()?;
        if records.len() > 4096 {
            return Err(Error::InvalidData("synced inventory exceeds limit".into()));
        }
        for id in &records {
            self.filename(id)?;
        }
        self.write_inventory(owner, &records.into_iter().collect())
    }
    fn include_synced_record(&self, id: &str, owner: u32) -> Result<()> {
        if let Some(mut records) = self.synced_inventory(owner)? {
            records.insert(id.into());
            self.write_inventory(owner, &records)?;
        }
        Ok(())
    }
    pub(super) fn update_lock(&self) -> Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.directory.join(".update.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        fs2::FileExt::try_lock_exclusive(&file)
            .map_err(|_| Error::Refused("another registry update is active".into()))?;
        Ok(file)
    }
    /// Return metadata only. Authentication material remains encrypted per item.
    /// The registry is paired with one UID; an unexpected owner is an error.
    pub fn browser_credentials(&self, owner: u32) -> Result<Vec<PasskeyCredential>> {
        let inventory = self.synced_inventory(owner)?;
        let mut records = Vec::new();
        let mut scanned = 0;
        for entry in
            std::fs::read_dir(&self.directory).map_err(|e| Error::io(&self.directory, e))?
        {
            let entry = entry.map_err(|e| Error::io(&self.directory, e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(id) = name.strip_suffix(".enc") else {
                continue;
            };
            if id.ends_with(".pending") {
                continue;
            }
            if matches!(id, "item-recipient" | "synced-inventory") {
                continue;
            }
            if id.starts_with("upload-")
                || id.starts_with("synced-create-")
                || id.starts_with("account-")
                || id.starts_with("login-")
                || id.starts_with("removed-")
            {
                continue;
            }
            scanned += 1;
            if scanned > 4096 {
                return Err(Error::Refused("broker inventory exceeds limit".into()));
            }
            if let Some(id) = id.strip_prefix("protected-") {
                if self.synced_creation_summary(id, owner)?.is_some() {
                    continue;
                }
                let record = self.load_protected(id, owner)?;
                if !record.diagnostic
                    && record.verified
                    && inventory
                        .as_ref()
                        .is_none_or(|records| records.contains(id))
                {
                    records.push(record.credential);
                }
            } else {
                if self.removed_for_owner(id, owner)? {
                    continue;
                }
                let record = self.load(id, owner)?;
                if !record.diagnostic && record.registered {
                    records.push(record.credential);
                }
            }
        }
        Ok(records)
    }
    pub fn open(directory: &Path) -> Result<Self> {
        let meta = std::fs::symlink_metadata(directory).map_err(|e| Error::io(directory, e))?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != 0
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(Error::Security(
                "broker registry must be a private root-owned directory".into(),
            ));
        }
        let paths = AppPaths::new(
            directory.join("config"),
            directory.join("state"),
            directory.join("runtime"),
        )?;
        refuse_missing_root(directory, &paths.software_key_file())?;
        let root = RegistryRoot {
            directory: directory.into(),
            key_path: paths.software_key_file(),
            inner: crate::security::FileRootKeySource::new(paths.clone()),
            initialized: std::sync::atomic::AtomicBool::new(
                paths
                    .software_key_file()
                    .try_exists()
                    .map_err(|e| Error::io(paths.software_key_file(), e))?,
            ),
        };
        Ok(Self {
            directory: directory.to_owned(),
            backend: SoftwareFileBackend::with_root_source(paths, Box::new(root)),
        })
    }
    pub fn provision_diagnostic(&self, owner: u32, key: StoredSepKey) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let reference = key.reference().clone();
        let record = Record {
            version: 1,
            owner,
            diagnostic: true,
            registered: false,
            creation_binding: None,
            credential: PasskeyCredential {
                provenance: PasskeyProvenance::DeviceBound,
                id: id.clone(),
                rp_id: "diagnostic.invalid".into(),
                credential_id: URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
                user_handle: URL_SAFE_NO_PAD.encode(owner.to_be_bytes()),
                username: "Disposable key".into(),
                display_name: "Disposable key".into(),
                created_at: 0.0,
                modified_at: 0.0,
                signing_key: reference,
            },
            native_key: key,
        };
        self.save_new(&record)?;
        Ok(id)
    }
    fn filename(&self, id: &str) -> Result<PathBuf> {
        crate::paths::validate_record_id(id)?;
        self.refuse_removed(id)?;
        Ok(self.directory.join(format!("{id}.enc")))
    }
    pub fn load(&self, id: &str, owner: u32) -> Result<Record> {
        let path = self.filename(id)?;
        let data = read_bounded(&path)?;
        if data.len() > 64 * 1024 {
            return Err(Error::InvalidData("broker record exceeds limit".into()));
        }
        let plain = self.backend.open(Purpose::Vault, &data)?;
        let record: Record = serde_json::from_slice(&plain)?;
        if record.version != 1
            || record.owner != owner
            || record.credential.id != id
            || record.credential.signing_key != *record.native_key.reference()
            || record.credential.provenance != PasskeyProvenance::DeviceBound
            || record.creation_binding.as_ref().is_some_and(|binding| {
                record.diagnostic || binding.len() != 64 || hex::decode(binding).is_err()
            })
        {
            return Err(Error::Security(
                "broker record identity/policy mismatch".into(),
            ));
        }
        record.native_key.public_sec1()?;
        Ok(record)
    }
    fn save_new(&self, record: &Record) -> Result<()> {
        self.refuse_login_collision(&record.credential.id)?;
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(record)?);
        let sealed = self.backend.seal(Purpose::Vault, &plain)?;
        create_private_exclusive(&self.filename(&record.credential.id)?, &sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    #[ignore = "requires root; only temporary synthetic upload metadata, no SEP or network"]
    fn upload_journal_is_not_a_credential_and_prevents_in_process_root_replacement() -> Result<()> {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let directory = tempfile::tempdir().map_err(|e| Error::io("test registry", e))?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(directory.path(), e))?;
        let registry = Registry::open(directory.path())?;
        let envelope = registry
            .backend
            .seal(Purpose::SyncUpload, b"synthetic journal marker")?;
        let journal = directory
            .path()
            .join(format!("upload-{}.enc", Uuid::new_v4()));
        create_private_exclusive(&journal, &envelope)?;
        assert!(registry.browser_credentials(1001)?.is_empty());
        assert!(registry.uploads().is_ok());
        let root = directory.path().join("state/software.key");
        std::fs::remove_file(&root).map_err(|e| Error::io(&root, e))?;
        assert!(
            registry
                .backend
                .seal(Purpose::SyncUpload, b"must refuse")
                .is_err()
        );
        assert!(Registry::open(directory.path()).is_err());
        std::fs::remove_file(&journal).map_err(|e| Error::io(&journal, e))?;
        assert!(
            registry
                .backend
                .seal(Purpose::SyncUpload, b"even without a remaining envelope")
                .is_err()
        );
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    #[ignore = "requires root; creates only disposable temporary registry files"]
    fn root_registry_enforces_owner_identity_and_authenticated_storage() {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("private directory: {e}"));
        let registry = Registry::open(dir.path()).unwrap_or_else(|e| panic!("registry: {e}"));
        let scalar =
            p256::SecretKey::from_slice(&[7; 32]).unwrap_or_else(|e| panic!("synthetic key: {e}"));
        let key: StoredSepKey = serde_json::from_value(serde_json::json!({
            "version": 1, "reference": crate::security::KeyRef {
                backend_id: "sep-native-v1".into(), key_id: Uuid::new_v4().to_string(),
                usage: crate::security::KeyUsage::WebAuthnSigning, algorithm: crate::security::KeyAlgorithm::P256 },
            "policy":"biometry-any", "wrapped_blob": STANDARD.encode(b"synthetic wrapped blob"),
            "public_sec1":STANDARD.encode(scalar.public_key().to_encoded_point(false).as_bytes()), "allow_decrypt":false
        })).unwrap_or_else(|e| panic!("fixture: {e}"));
        let id = registry
            .provision_diagnostic(1001, key)
            .unwrap_or_else(|e| panic!("provision: {e}"));
        assert!(registry.load(&id, 1001).is_ok());
        assert!(registry.load(&id, 1002).is_err());
        assert!(registry.load("../../software.key", 1001).is_err());
        let path = registry
            .filename(&id)
            .unwrap_or_else(|e| panic!("path: {e}"));
        let mut encrypted = read_bounded(&path).unwrap_or_else(|e| panic!("read: {e}"));
        let last = encrypted.len() - 1;
        encrypted[last] ^= 1;
        crate::paths::atomic_write_private(&path, &encrypted)
            .unwrap_or_else(|e| panic!("mutate: {e}"));
        assert!(registry.load(&id, 1001).is_err());
        std::fs::remove_file(dir.path().join("state/software.key"))
            .unwrap_or_else(|e| panic!("remove synthetic root: {e}"));
        assert!(Registry::open(dir.path()).is_err());
        assert!(
            registry
                .backend
                .seal(Purpose::Vault, b"must not regenerate in a running broker")
                .is_err()
        );
        assert!(!dir.path().join("state/software.key").exists());
    }
}
