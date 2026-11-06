use super::Registry;
use crate::model::{PasskeyCredential, PasskeyProvenance};
use crate::paths::{atomic_write_private, create_private_exclusive, read_bounded};
use crate::security::sep::StoredSepKey;
use crate::security::{KeyAlgorithm, KeyRef, KeyUsage, Purpose, SecurityBackend};
use crate::{Error, Result};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use keychain_sep_driver::Device;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub id: String,
    pub public_sec1: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedImport {
    pub expected_revision: u64,
    pub recipient_id: String,
    pub credential: PasskeyCredential,
    pub public_sec1: String,
    /// Ciphertext only. Scalar material is never serialized in the broker protocol.
    pub sealed: Vec<u8>,
    pub diagnostic: bool,
}

impl ProtectedImport {
    /// Encrypt an existing syncable scalar on the client. The resulting request
    /// contains only ciphertext; this operation does not delete its source key.
    pub fn seal_scalar(
        owner: u32,
        recipient: &Recipient,
        expected_revision: u64,
        credential: PasskeyCredential,
        scalar: &[u8],
        diagnostic: bool,
    ) -> Result<Self> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        if scalar.len() != 32 {
            return Err(Error::InvalidData("expected a 32-byte P-256 scalar".into()));
        }
        let key = p256::SecretKey::from_slice(scalar)
            .map_err(|_| Error::InvalidData("invalid P-256 scalar".into()))?;
        let public_sec1 = STANDARD.encode(key.public_key().to_encoded_point(false).as_bytes());
        drop(key);
        let revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| Error::InvalidData("record revision overflow".into()))?;
        let binding = item_binding(owner, revision, &recipient.id, &credential, &public_sec1)?;
        let sealed = crate::security::sep::envelope::seal_item(
            &decode_public(&recipient.public_sec1)?,
            &binding,
            scalar,
        )?;
        Ok(Self {
            expected_revision,
            recipient_id: recipient.id.clone(),
            credential,
            public_sec1,
            sealed,
            diagnostic,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRecord {
    pub version: u32,
    pub owner: u32,
    pub revision: u64,
    pub recipient_id: String,
    pub credential: PasskeyCredential,
    pub public_sec1: String,
    pub sealed: Vec<u8>,
    pub diagnostic: bool,
    pub verified: bool,
}
impl ProtectedRecord {
    pub(crate) fn validate(&self, id: &str, owner: u32) -> Result<()> {
        if self.version != 1
            || self.owner != owner
            || self.credential.id != id
            || self.revision == 0
            || self.credential.provenance != PasskeyProvenance::Synced
            || self.credential.signing_key.backend_id != "sep-protected-software-v1"
            || self.credential.signing_key.key_id != id
            || self.credential.signing_key.algorithm != KeyAlgorithm::P256
            || self.credential.signing_key.usage != KeyUsage::WebAuthnSigning
            || !(81..=4096).contains(&self.sealed.len())
        {
            return Err(Error::Security(
                "protected record identity/policy mismatch".into(),
            ));
        }
        item_binding(
            owner,
            self.revision,
            &self.recipient_id,
            &self.credential,
            &self.public_sec1,
        )?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedSummary {
    pub credential: PasskeyCredential,
    pub public_sec1: String,
    pub revision: u64,
    pub recipient_id: String,
    pub verified: bool,
    pub diagnostic: bool,
}
impl From<ProtectedRecord> for ProtectedSummary {
    fn from(record: ProtectedRecord) -> Self {
        Self {
            credential: record.credential,
            public_sec1: record.public_sec1,
            revision: record.revision,
            recipient_id: record.recipient_id,
            verified: record.verified,
            diagnostic: record.diagnostic,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionState {
    pub active: Option<ProtectedSummary>,
    pub staged: Option<ProtectedSummary>,
}

/// Canonical JSON field order is fixed by this struct, not a caller's map order.
/// The binding is immutable for a stored revision and contains no scalar data.
pub fn item_binding(
    owner: u32,
    revision: u64,
    recipient_id: &str,
    credential: &PasskeyCredential,
    public_sec1: &str,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Binding<'a> {
        application: &'static str,
        version: u32,
        owner: u32,
        record: &'a str,
        revision: u64,
        recipient: &'a str,
        rp: &'a str,
        credential_sha256: String,
        user_handle_sha256: String,
        public_sha256: String,
        purpose: &'static str,
        algorithm: &'static str,
    }
    let credential_id = crate::passkey::credential_id(credential)?;
    let user_handle = crate::passkey::user_handle(credential)?;
    let public = decode_public(public_sec1)?;
    let binding = serde_json::to_vec(&Binding {
        application: "cameroncooper.keychain",
        version: 1,
        owner,
        record: &credential.id,
        revision,
        recipient: recipient_id,
        rp: &credential.rp_id,
        credential_sha256: hex::encode(Sha256::digest(&credential_id)),
        user_handle_sha256: hex::encode(Sha256::digest(&user_handle)),
        public_sha256: hex::encode(Sha256::digest(public)),
        purpose: "synced-passkey-scalar",
        algorithm: "p256",
    })?;
    if binding.len() > 1024 {
        return Err(Error::InvalidData(
            "item binding exceeds envelope limit".into(),
        ));
    }
    Ok(binding)
}

pub fn decode_public(value: &str) -> Result<Vec<u8>> {
    let public = STANDARD
        .decode(value)
        .map_err(|_| Error::InvalidData("invalid imported public key encoding".into()))?;
    if public.len() != 65
        || public.first() != Some(&4)
        || p256::PublicKey::from_sec1_bytes(&public).is_err()
    {
        return Err(Error::InvalidData(
            "invalid imported P-256 public point".into(),
        ));
    }
    Ok(public)
}

impl Registry {
    pub fn protection_state(&self, id: &str, owner: u32) -> Result<ProtectionState> {
        let _lock = self.update_lock()?;
        let active = self.protected_filename(id)?;
        let pending = self.pending_filename(id)?;
        let draft = self.synced_creation_summary(id, owner)?;
        Ok(ProtectionState {
            active: if draft.is_none() && active.try_exists().map_err(|e| Error::io(&active, e))? {
                Some(self.read_protected(&active, id, owner)?.into())
            } else {
                None
            },
            staged: if pending.try_exists().map_err(|e| Error::io(&pending, e))? {
                Some(self.read_protected(&pending, id, owner)?.into())
            } else {
                draft
            },
        })
    }
    pub fn refresh_protected_metadata(
        &self,
        owner: u32,
        credential: PasskeyCredential,
        public: &str,
        revision: u64,
    ) -> Result<()> {
        let _lock = self.update_lock()?;
        let mut record = self.load_protected(&credential.id, owner)?;
        if record.diagnostic
            || !record.verified
            || record.revision != revision
            || record.public_sec1 != public
            || !crate::protection::same_identity(&record.credential, &credential)
            || record.credential.signing_key != credential.signing_key
        {
            return Err(Error::Refused(
                "sync metadata does not match the protected identity".into(),
            ));
        }
        if self.pending_filename(&credential.id)?.exists() {
            return Err(Error::Refused(
                "complete the staged import before refreshing metadata".into(),
            ));
        }
        if [&credential.username, &credential.display_name]
            .iter()
            .any(|s| s.len() > 4096 || s.chars().any(char::is_control))
            || !credential.created_at.is_finite()
            || !credential.modified_at.is_finite()
            || credential.modified_at < record.credential.modified_at
        {
            return Err(Error::InvalidData(
                "invalid or stale synced metadata".into(),
            ));
        }
        record.credential = credential;
        self.write_protected(&record, true)
    }
    pub(super) fn protected_filename(&self, id: &str) -> Result<PathBuf> {
        self.filename(id)?;
        Ok(self.directory.join(format!("protected-{id}.enc")))
    }
    pub(super) fn pending_filename(&self, id: &str) -> Result<PathBuf> {
        self.filename(id)?;
        Ok(self.directory.join(format!("protected-{id}.pending.enc")))
    }
    /// Explicit root setup only: loss of a recipient never creates a replacement.
    pub fn provision_item_recipient(&self, device: &mut Device) -> Result<Recipient> {
        let _lock = self.update_lock()?;
        let path = self.directory.join("item-recipient.enc");
        if path.exists() {
            return self.item_recipient();
        }
        for entry in
            std::fs::read_dir(&self.directory).map_err(|e| Error::io(&self.directory, e))?
        {
            let entry = entry.map_err(|e| Error::io(&self.directory, e))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("protected-") || name.starts_with("synced-create-") {
                return Err(Error::Security(
                    "item recipient is missing while protected records exist; refusing replacement"
                        .into(),
                ));
            }
        }
        let key = StoredSepKey::create_for_policy(device, true)?;
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&key)?);
        let encrypted = self.backend.seal(Purpose::KeyStore, &plain)?;
        create_private_exclusive(&path, &encrypted)?;
        self.item_recipient()
    }
    pub fn item_key(&self) -> Result<StoredSepKey> {
        let path = self.directory.join("item-recipient.enc");
        let data = read_bounded(&path)?;
        if data.len() > 16 * 1024 {
            return Err(Error::InvalidData("item recipient exceeds limit".into()));
        }
        let plain = self.backend.open(Purpose::KeyStore, &data)?;
        let key: StoredSepKey = serde_json::from_slice(&plain)?;
        key.validate_for_decrypt()?;
        Ok(key)
    }
    pub fn item_recipient(&self) -> Result<Recipient> {
        let key = self.item_key()?;
        Ok(Recipient {
            id: key.reference().key_id.clone(),
            public_sec1: STANDARD.encode(key.public_sec1()?),
        })
    }
    pub fn import_protected(&self, owner: u32, mut import: ProtectedImport) -> Result<u64> {
        let _lock = self.update_lock()?;
        let id = import.credential.id.clone();
        if self.synced_creation_summary(&id, owner)?.is_some() {
            return Err(Error::Refused(
                "registration owns this credential; resume it instead of replacing its key".into(),
            ));
        }
        let path = self.protected_filename(&id)?;
        let pending = self.pending_filename(&id)?;
        if pending.try_exists().map_err(|e| Error::io(&pending, e))? {
            return Err(Error::Refused(
                "a staged import already exists; verify or explicitly discard it first".into(),
            ));
        }
        if import.credential.provenance != PasskeyProvenance::Synced
            || import.credential.rp_id.len() > 253
            || crate::passkey::normalize_rp_id(&import.credential.rp_id)
                .map_err(Error::InvalidData)?
                != import.credential.rp_id
            || [&import.credential.username, &import.credential.display_name]
                .iter()
                .any(|s| s.len() > 4096 || s.chars().any(char::is_control))
            || !import.credential.created_at.is_finite()
            || !import.credential.modified_at.is_finite()
            || !(81..=4096).contains(&import.sealed.len())
            || import.sealed[0] != 4
        {
            return Err(Error::InvalidData(
                "invalid protected credential metadata or ciphertext".into(),
            ));
        }
        let credential_id = crate::passkey::credential_id(&import.credential)?;
        let handle = crate::passkey::user_handle(&import.credential)?;
        if !(1..=4096).contains(&credential_id.len())
            || !(1..=64).contains(&handle.len())
            || URL_SAFE_NO_PAD.encode(&credential_id) != import.credential.credential_id
            || URL_SAFE_NO_PAD.encode(&handle) != import.credential.user_handle
        {
            return Err(Error::InvalidData(
                "invalid imported credential ID or user handle".into(),
            ));
        }
        let recipient = self.item_recipient()?;
        if recipient.id != import.recipient_id {
            return Err(Error::Security("wrong protected-item recipient".into()));
        }
        let revision = import
            .expected_revision
            .checked_add(1)
            .ok_or_else(|| Error::InvalidData("record revision overflow".into()))?;
        if path.exists() {
            let previous = self.load_protected(&id, owner)?;
            if previous.revision != import.expected_revision
                || previous.credential.rp_id != import.credential.rp_id
                || previous.credential.credential_id != import.credential.credential_id
                || previous.credential.user_handle != import.credential.user_handle
                || previous.public_sec1 != import.public_sec1
                || previous.diagnostic != import.diagnostic
            {
                return Err(Error::Refused(
                    "stale revision or changed credential identity".into(),
                ));
            }
        } else if import.expected_revision != 0 {
            return Err(Error::Refused(
                "protected record does not exist at expected revision".into(),
            ));
        }
        import.credential.signing_key = KeyRef {
            backend_id: "sep-protected-software-v1".into(),
            key_id: id,
            usage: KeyUsage::WebAuthnSigning,
            algorithm: KeyAlgorithm::P256,
        };
        item_binding(
            owner,
            revision,
            &recipient.id,
            &import.credential,
            &import.public_sec1,
        )?;
        let record = ProtectedRecord {
            version: 1,
            owner,
            revision,
            recipient_id: recipient.id,
            credential: import.credential,
            public_sec1: import.public_sec1,
            sealed: import.sealed,
            diagnostic: import.diagnostic,
            verified: false,
        };
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&record)?);
        // The update lock and absence check above protect this new slot. Rename
        // only a fully written/fsynced envelope into the staging namespace.
        atomic_write_private(&pending, &self.backend.seal(Purpose::Vault, &plain)?)?;
        Ok(revision)
    }
    pub fn load_protected(&self, id: &str, owner: u32) -> Result<ProtectedRecord> {
        self.refuse_uncommitted_creation(id, owner)?;
        let path = self.protected_filename(id)?;
        self.read_protected(&path, id, owner)
    }
    pub fn verification_record(&self, id: &str, owner: u32) -> Result<ProtectedRecord> {
        self.refuse_uncommitted_creation(id, owner)?;
        let pending = self.pending_filename(id)?;
        if pending.try_exists().map_err(|e| Error::io(&pending, e))? {
            self.read_protected(&pending, id, owner)
        } else {
            self.load_protected(id, owner)
        }
    }
    fn refuse_uncommitted_creation(&self, id: &str, owner: u32) -> Result<()> {
        if self.synced_creation_summary(id, owner)?.is_some() {
            return Err(Error::Refused(
                "synced registration is not committed".into(),
            ));
        }
        Ok(())
    }
    pub(super) fn read_protected(
        &self,
        path: &std::path::Path,
        id: &str,
        owner: u32,
    ) -> Result<ProtectedRecord> {
        let data = read_bounded(path)?;
        if data.len() > 64 * 1024 {
            return Err(Error::InvalidData("protected record exceeds limit".into()));
        }
        let plain = self.backend.open(Purpose::Vault, &data)?;
        let record: ProtectedRecord = serde_json::from_slice(&plain)?;
        record.validate(id, owner)?;
        Ok(record)
    }
    pub(crate) fn commit_verified(&self, expected: &ProtectedRecord) -> Result<()> {
        let _lock = self.update_lock()?;
        let id = &expected.credential.id;
        let owner = expected.owner;
        let revision = expected.revision;
        let mut record = self.verification_record(id, owner)?;
        if serde_json::to_vec(&record)? != serde_json::to_vec(expected)? {
            return Err(Error::Refused("record changed during verification".into()));
        }
        let active_path = self.protected_filename(id)?;
        if active_path
            .try_exists()
            .map_err(|e| Error::io(&active_path, e))?
        {
            let active = self.load_protected(id, owner)?;
            if active.revision != revision && active.revision.checked_add(1) != Some(revision) {
                return Err(Error::Refused(
                    "active record changed during verification".into(),
                ));
            }
            if active.revision == revision
                && (active.sealed != record.sealed || active.public_sec1 != record.public_sec1)
            {
                return Err(Error::Refused("same revision has different content".into()));
            }
        } else if revision != 1 {
            return Err(Error::Refused(
                "previous committed revision is missing".into(),
            ));
        }
        record.verified = true;
        // Atomic authenticated commit precedes removal of the staging file. A
        // crash here leaves either the old active key or this verified successor.
        self.write_protected(&record, true)?;
        self.include_synced_record(id, owner)?;
        let pending = self.pending_filename(id)?;
        match std::fs::remove_file(&pending) {
            Ok(()) => std::fs::File::open(&self.directory)
                .and_then(|d| d.sync_all())
                .map_err(|e| Error::io(&self.directory, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(&pending, e)),
        }
    }
    pub fn discard_staged(&self, id: &str, owner: u32, revision: u64) -> Result<()> {
        let _lock = self.update_lock()?;
        let path = self.pending_filename(id)?;
        let record = self.read_protected(&path, id, owner)?;
        if record.revision != revision {
            return Err(Error::Refused("staged revision changed".into()));
        }
        std::fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
        std::fs::File::open(&self.directory)
            .and_then(|d| d.sync_all())
            .map_err(|e| Error::io(&self.directory, e))
    }
    pub(super) fn write_protected(&self, record: &ProtectedRecord, replace: bool) -> Result<()> {
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(record)?);
        let encrypted = self.backend.seal(Purpose::Vault, &plain)?;
        let path = self.protected_filename(&record.credential.id)?;
        if replace {
            atomic_write_private(&path, &encrypted)
        } else {
            create_private_exclusive(&path, &encrypted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use std::os::unix::fs::PermissionsExt;

    pub(super) fn fixture() -> (Recipient, PasskeyCredential) {
        let key = p256::SecretKey::from_slice(&[7; 32]).unwrap_or_else(|e| panic!("fixture: {e}"));
        let id = uuid::Uuid::new_v4().to_string().to_ascii_uppercase();
        (
            Recipient {
                id: uuid::Uuid::new_v4().to_string(),
                public_sec1: STANDARD.encode(key.public_key().to_encoded_point(false).as_bytes()),
            },
            PasskeyCredential {
                id: id.clone(),
                rp_id: "example.com".into(),
                provenance: PasskeyProvenance::Synced,
                credential_id: URL_SAFE_NO_PAD.encode([1; 16]),
                user_handle: URL_SAFE_NO_PAD.encode([2; 16]),
                username: "Example".into(),
                display_name: "Example".into(),
                created_at: 0.0,
                modified_at: 0.0,
                signing_key: KeyRef {
                    backend_id: "sep-protected-software-v1".into(),
                    key_id: id,
                    usage: KeyUsage::WebAuthnSigning,
                    algorithm: KeyAlgorithm::P256,
                },
            },
        )
    }
    #[test]
    fn binding_covers_credential_identity_owner_recipient_and_revision() {
        let (recipient, credential) = fixture();
        let binding = |owner, revision, recipient: &str, c: &PasskeyCredential| {
            item_binding(owner, revision, recipient, c, &fixture().0.public_sec1)
                .unwrap_or_else(|e| panic!("binding: {e}"))
        };
        let original = binding(1001, 1, &recipient.id, &credential);
        assert_ne!(original, binding(1002, 1, &recipient.id, &credential));
        assert_ne!(original, binding(1001, 2, &recipient.id, &credential));
        assert_ne!(
            original,
            binding(1001, 1, "different-recipient", &credential)
        );
        for field in 0..4 {
            let mut changed = credential.clone();
            match field {
                0 => changed.id = uuid::Uuid::new_v4().to_string(),
                1 => changed.rp_id = "other.example".into(),
                2 => changed.credential_id = URL_SAFE_NO_PAD.encode([3; 16]),
                _ => changed.user_handle = URL_SAFE_NO_PAD.encode([4; 16]),
            }
            assert_ne!(original, binding(1001, 1, &recipient.id, &changed));
        }
        let import = ProtectedImport::seal_scalar(1001, &recipient, 0, credential, &[9; 32], true)
            .unwrap_or_else(|e| panic!("seal: {e}"));
        let wire = serde_json::to_value(&import).unwrap_or_else(|e| panic!("wire: {e}"));
        assert!(wire.get("scalar").is_none());
        assert_ne!(import.sealed, &[9; 32]);
        assert!(
            ProtectedImport::seal_scalar(
                1001,
                &recipient,
                u64::MAX,
                import.credential,
                &[9; 32],
                true
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "requires root; synthetic temporary registry only, no SEP access"]
    fn root_protected_registry_enforces_revision_identity_and_no_unverified_replacement() {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("mode: {e}"));
        let registry = Registry::open(dir.path()).unwrap_or_else(|e| panic!("registry: {e}"));
        let (recipient, credential) = fixture();
        let key:StoredSepKey=serde_json::from_value(serde_json::json!({
            "version":1,"reference":KeyRef{backend_id:"sep-native-v1".into(),key_id:recipient.id.clone(),usage:KeyUsage::WebAuthnSigning,algorithm:KeyAlgorithm::P256},
            "policy":"biometry-any","wrapped_blob":STANDARD.encode(b"synthetic wrapped blob"),"public_sec1":recipient.public_sec1,"allow_decrypt":true
        })).unwrap_or_else(|e|panic!("key: {e}"));
        let plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&key).unwrap_or_else(|e| panic!("serialize: {e}")),
        );
        let encrypted = registry
            .backend
            .seal(Purpose::KeyStore, &plain)
            .unwrap_or_else(|e| panic!("seal: {e}"));
        create_private_exclusive(&dir.path().join("item-recipient.enc"), &encrypted)
            .unwrap_or_else(|e| panic!("write: {e}"));
        let import = |revision, c: PasskeyCredential| {
            ProtectedImport::seal_scalar(1001, &recipient, revision, c, &[9; 32], false)
                .unwrap_or_else(|e| panic!("import: {e}"))
        };
        assert_eq!(
            registry
                .import_protected(1001, import(0, credential.clone()))
                .unwrap_or_else(|e| panic!("initial import: {e}")),
            1
        );
        assert!(registry.load_protected(&credential.id, 1002).is_err());
        assert!(registry.load_protected(&credential.id, 1001).is_err());
        assert!(
            registry
                .browser_credentials(1001)
                .unwrap_or_else(|e| panic!("metadata: {e}"))
                .is_empty()
        );
        assert!(
            registry
                .import_protected(1001, import(0, credential.clone()))
                .is_err()
        );
        let candidate = registry
            .verification_record(&credential.id, 1001)
            .unwrap_or_else(|e| panic!("staged: {e}"));
        registry
            .commit_verified(&candidate)
            .unwrap_or_else(|e| panic!("commit: {e}"));
        let mut metadata = credential.clone();
        metadata.username = "updated@example.com".into();
        metadata.modified_at = 3.0;
        registry
            .refresh_protected_metadata(1001, metadata.clone(), &candidate.public_sec1, 1)
            .unwrap_or_else(|e| panic!("metadata update: {e}"));
        let mut wrong_identity = metadata.clone();
        wrong_identity.rp_id = "attacker.example".into();
        assert!(
            registry
                .refresh_protected_metadata(1001, wrong_identity, &candidate.public_sec1, 1)
                .is_err()
        );
        assert!(
            registry
                .refresh_protected_metadata(1001, metadata, &candidate.public_sec1, 2)
                .is_err()
        );
        registry
            .set_synced_inventory(1001, vec![])
            .unwrap_or_else(|e| panic!("disable snapshot: {e}"));
        assert!(
            registry
                .browser_credentials(1001)
                .unwrap_or_else(|e| panic!("disabled metadata: {e}"))
                .is_empty()
        );
        assert!(registry.load_protected(&credential.id, 1001).is_ok());
        registry
            .set_synced_inventory(1001, vec![credential.id.clone()])
            .unwrap_or_else(|e| panic!("enable snapshot: {e}"));
        assert_eq!(
            registry
                .browser_credentials(1001)
                .unwrap_or_else(|e| panic!("metadata: {e}"))
                .len(),
            1
        );
        let mut changed = credential.clone();
        changed.rp_id = "other.example".into();
        assert!(registry.import_protected(1001, import(1, changed)).is_err());
        assert_eq!(
            registry
                .import_protected(1001, import(1, credential.clone()))
                .unwrap_or_else(|e| panic!("stage replacement: {e}")),
            2
        );
        // Restart after staging: the previous verified key remains active.
        drop(registry);
        let registry =
            Registry::open(dir.path()).unwrap_or_else(|e| panic!("restart after staging: {e}"));
        assert_eq!(
            registry
                .load_protected(&credential.id, 1001)
                .unwrap_or_else(|e| panic!("active: {e}"))
                .revision,
            1
        );
        assert!(registry.commit_verified(&candidate).is_err());
        assert!(registry.discard_staged(&credential.id, 1002, 2).is_err());
        let candidate = registry
            .verification_record(&credential.id, 1001)
            .unwrap_or_else(|e| panic!("candidate: {e}"));
        let staged_path = registry
            .pending_filename(&credential.id)
            .unwrap_or_else(|e| panic!("path: {e}"));
        let staged_ciphertext =
            read_bounded(&staged_path).unwrap_or_else(|e| panic!("staged ciphertext: {e}"));
        registry
            .commit_verified(&candidate)
            .unwrap_or_else(|e| panic!("verify replacement: {e}"));
        // Simulate interruption after the durable active commit but before
        // staging removal. Recovery re-verifies the same candidate and is idempotent.
        create_private_exclusive(&staged_path, &staged_ciphertext)
            .unwrap_or_else(|e| panic!("interrupted cleanup: {e}"));
        drop(registry);
        let registry =
            Registry::open(dir.path()).unwrap_or_else(|e| panic!("restart after commit: {e}"));
        assert_eq!(
            registry
                .load_protected(&credential.id, 1001)
                .unwrap_or_else(|e| panic!("committed: {e}"))
                .revision,
            2
        );
        registry
            .commit_verified(&candidate)
            .unwrap_or_else(|e| panic!("recover cleanup: {e}"));
        assert!(!staged_path.exists());
        assert!(
            registry
                .load_protected(&credential.id, 1001)
                .unwrap_or_else(|e| panic!("reload: {e}"))
                .verified
        );
        std::fs::remove_file(dir.path().join("item-recipient.enc"))
            .unwrap_or_else(|e| panic!("remove synthetic recipient: {e}"));
        assert!(registry.item_recipient().is_err());
        assert!(registry.load_protected("../../anything", 1001).is_err());
    }
}
