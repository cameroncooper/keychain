//! Revisioned selected login envelopes. No login plaintext is stored here.
use super::*;
use crate::broker::login::{LoginImport, LoginMetadata, login_binding};
use std::io;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LoginRecord {
    pub version: u32,
    pub owner: u32,
    pub revision: u64,
    pub recipient_id: String,
    pub metadata: LoginMetadata,
    pub content_binding: String,
    pub sealed: Vec<u8>,
    pub verified: bool,
}
impl LoginRecord {
    fn validate(&self, id: &str, owner: u32) -> Result<()> {
        if self.version != 1
            || self.owner != owner
            || self.metadata.id != id
            || self.revision == 0
            || !(81..=4096).contains(&self.sealed.len())
            || self.sealed.first() != Some(&4)
        {
            return Err(Error::Security(
                "protected login identity/policy mismatch".into(),
            ));
        }
        login_binding(
            owner,
            self.revision,
            &self.recipient_id,
            &self.metadata,
            &self.content_binding,
        )?;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginSummary {
    pub metadata: LoginMetadata,
    pub content_binding: String,
    pub revision: u64,
    pub recipient_id: String,
    pub verified: bool,
}
impl From<LoginRecord> for LoginSummary {
    fn from(record: LoginRecord) -> Self {
        Self {
            metadata: record.metadata,
            content_binding: record.content_binding,
            revision: record.revision,
            recipient_id: record.recipient_id,
            verified: record.verified,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginState {
    pub active: Option<LoginSummary>,
    pub staged: Option<LoginSummary>,
}
impl Registry {
    pub(super) fn login_path(&self, id: &str, pending: bool) -> Result<PathBuf> {
        self.filename(id)?;
        Ok(self.directory.join(format!(
            "login-{id}{}.enc",
            if pending { ".pending" } else { "" }
        )))
    }
    fn read_login(&self, id: &str, owner: u32, pending: bool) -> Result<LoginRecord> {
        let path = self.login_path(id, pending)?;
        let bytes = read_bounded(&path)?;
        if bytes.len() > 32768 {
            return Err(Error::InvalidData("login record exceeds limit".into()));
        }
        let plain = self.backend.open(Purpose::BrokerLogin, &bytes)?;
        let record: LoginRecord = serde_json::from_slice(&plain)?;
        record.validate(id, owner)?;
        Ok(record)
    }
    pub fn load_login(&self, id: &str, owner: u32) -> Result<LoginRecord> {
        self.read_login(id, owner, false)
    }
    pub fn login_verification_record(&self, id: &str, owner: u32) -> Result<LoginRecord> {
        let path = self.login_path(id, true)?;
        if path.try_exists().map_err(|e| Error::io(&path, e))? {
            self.read_login(id, owner, true)
        } else {
            self.load_login(id, owner)
        }
    }
    pub fn login_state(&self, id: &str, owner: u32) -> Result<LoginState> {
        let _lock = self.update_lock()?;
        let read = |pending| -> Result<Option<LoginSummary>> {
            let path = self.login_path(id, pending)?;
            if path.try_exists().map_err(|e| Error::io(&path, e))? {
                Ok(Some(self.read_login(id, owner, pending)?.into()))
            } else {
                Ok(None)
            }
        };
        Ok(LoginState {
            active: read(false)?,
            staged: read(true)?,
        })
    }
    pub fn login_metadata(&self, owner: u32) -> Result<Vec<LoginSummary>> {
        let _lock = self.update_lock()?;
        let mut logins = Vec::new();
        let mut scanned = 0;
        for entry in
            std::fs::read_dir(&self.directory).map_err(|e| Error::io(&self.directory, e))?
        {
            let entry = entry.map_err(|e| Error::io(&self.directory, e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(id) = name
                .strip_prefix("login-")
                .and_then(|name| name.strip_suffix(".enc"))
            else {
                continue;
            };
            scanned += 1;
            if scanned > 8192 {
                return Err(Error::Refused("login inventory exceeds limit".into()));
            }
            if id.ends_with(".pending") {
                continue;
            }
            let record = self.load_login(id, owner)?;
            if record.verified && self.synced_record_enabled(id, owner)? {
                logins.push(record.into());
            }
        }
        Ok(logins)
    }
    pub(super) fn refuse_login_collision(&self, id: &str) -> Result<()> {
        for pending in [false, true] {
            let path = self.login_path(id, pending)?;
            if path.try_exists().map_err(|e| Error::io(&path, e))? {
                return Err(Error::Refused("record belongs to a login".into()));
            }
        }
        Ok(())
    }
    pub fn import_login(&self, owner: u32, import: LoginImport) -> Result<u64> {
        let _lock = self.update_lock()?;
        let id = import.metadata.id.clone();
        let pending = self.login_path(&id, true)?;
        let active = self.login_path(&id, false)?;
        if pending.try_exists().map_err(|e| Error::io(&pending, e))? {
            return Err(Error::Refused(
                "a staged login already exists; verify or explicitly discard it first".into(),
            ));
        }
        // A UUID cannot change kinds by selecting another envelope namespace.
        for path in [
            self.filename(&id)?,
            self.protected_filename(&id)?,
            self.pending_filename(&id)?,
            self.directory.join(format!("{id}.pending.enc")),
        ] {
            if path.try_exists().map_err(|e| Error::io(&path, e))? {
                return Err(Error::Refused("record belongs to a passkey".into()));
            }
        }
        if self.synced_creation_exists(&id)? {
            return Err(Error::Refused(
                "record belongs to a passkey creation".into(),
            ));
        }
        let recipient = self.item_recipient()?;
        if recipient.id != import.recipient_id {
            return Err(Error::Security("wrong login recipient".into()));
        }
        let revision = import
            .expected_revision
            .checked_add(1)
            .ok_or_else(|| Error::InvalidData("login revision overflow".into()))?;
        if active.try_exists().map_err(|e| Error::io(&active, e))? {
            let previous = self.load_login(&id, owner)?;
            if !previous.verified
                || previous.revision != import.expected_revision
                || import.metadata.modified_at < previous.metadata.modified_at
            {
                return Err(Error::Refused("stale login revision or metadata".into()));
            }
        } else if import.expected_revision != 0 {
            return Err(Error::Refused(
                "previous committed login is missing; refusing replacement".into(),
            ));
        }
        let count = std::fs::read_dir(&self.directory)
            .map_err(|e| Error::io(&self.directory, e))?
            .try_fold(0usize, |count, entry| -> Result<usize> {
                let entry = entry.map_err(|e| Error::io(&self.directory, e))?;
                Ok(count
                    + usize::from(
                        entry
                            .path()
                            .extension()
                            .is_some_and(|extension| extension == "enc"),
                    ))
            })?;
        if count >= 8192 {
            return Err(Error::Refused("broker registry is full".into()));
        }
        let record = LoginRecord {
            version: 1,
            owner,
            revision,
            recipient_id: import.recipient_id,
            metadata: import.metadata,
            content_binding: import.content_binding,
            sealed: import.sealed,
            verified: false,
        };
        record.validate(&id, owner)?;
        self.write_login(&record, true)?;
        Ok(revision)
    }
    fn write_login(&self, record: &LoginRecord, pending: bool) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(record)?);
        let sealed = self.backend.seal(Purpose::BrokerLogin, &bytes)?;
        atomic_write_private(&self.login_path(&record.metadata.id, pending)?, &sealed)
    }
    pub(crate) fn check_current_login(&self, expected: &LoginRecord) -> Result<()> {
        if !expected.verified
            || &self.load_login(&expected.metadata.id, expected.owner)? != expected
        {
            return Err(Error::Refused("login changed during authorization".into()));
        }
        Ok(())
    }
    pub(crate) fn commit_verified_login(&self, expected: &LoginRecord) -> Result<()> {
        let _lock = self.update_lock()?;
        let mut current = self.login_verification_record(&expected.metadata.id, expected.owner)?;
        if &current != expected {
            return Err(Error::Refused("login changed during verification".into()));
        }
        let path = self.login_path(&expected.metadata.id, false)?;
        if path.try_exists().map_err(|e| Error::io(&path, e))? {
            let active = self.load_login(&expected.metadata.id, expected.owner)?;
            let mut verified = current.clone();
            verified.verified = true;
            if (active.revision == current.revision && active != verified)
                || (active.revision != current.revision
                    && active.revision.checked_add(1) != Some(current.revision))
            {
                return Err(Error::Refused(
                    "active login changed during verification".into(),
                ));
            }
        } else if current.revision != 1 {
            return Err(Error::Refused("previous committed login is missing".into()));
        }
        current.verified = true;
        self.write_login(&current, false)?;
        self.include_synced_record(&current.metadata.id, current.owner)?;
        self.remove_pending_login(&current.metadata.id)
    }
    pub fn discard_staged_login(&self, id: &str, owner: u32, revision: u64) -> Result<()> {
        let _lock = self.update_lock()?;
        if self.read_login(id, owner, true)?.revision != revision {
            return Err(Error::Refused("staged login changed".into()));
        }
        self.remove_pending_login(id)
    }
    fn remove_pending_login(&self, id: &str) -> Result<()> {
        let path = self.login_path(id, true)?;
        match std::fs::remove_file(&path) {
            Ok(()) => std::fs::File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| Error::io(&self.directory, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(&path, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::login::tests::{item, validate};
    #[test]
    #[ignore = "requires root; synthetic recipient/server only, no SEP/Apple IO"]
    fn root_login_staging_commit_recovery_revision_and_namespace_policy() -> Result<()> {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let directory = tempfile::tempdir().map_err(|e| Error::io("tempdir", e))?;
        let registry = super::super::test_support::registry(directory.path())?;
        let mut item = item();
        let id = item.id.clone();
        let recipient = registry.item_recipient()?;
        let mut wrong = LoginImport::seal(1001, &recipient, 0, &item)?;
        wrong.recipient_id = Uuid::new_v4().to_string();
        assert!(registry.import_login(1001, wrong).is_err());
        assert!(registry.login_state(&id, 1001)?.staged.is_none());
        let import = LoginImport::seal(1001, &recipient, 0, &item)?;
        assert_eq!(registry.import_login(1001, import)?, 1);
        assert!(registry.login_metadata(1001)?.is_empty());
        assert!(registry.browser_credentials(1001)?.is_empty());
        assert!(registry.login_state(&id, 1002).is_err());
        assert!(registry.refuse_login_collision(&id).is_err());
        assert!(
            registry
                .import_login(1001, LoginImport::seal(1001, &recipient, 0, &item)?)
                .is_err()
        );
        let staged = registry.login_verification_record(&id, 1001)?;
        validate(&staged)?; // Explicit synthetic stand-in for successful biometric delivery.
        let mut changed = staged.clone();
        changed.metadata.username = "changed".into();
        assert!(registry.commit_verified_login(&changed).is_err());
        registry.commit_verified_login(&staged)?;
        let reopened = Registry::open(directory.path())?;
        assert_eq!(reopened.login_metadata(1001)?.len(), 1);
        let active = reopened.load_login(&id, 1001)?;
        assert!(active.verified);
        reopened.check_current_login(&active)?;
        reopened.set_synced_inventory(1001, vec![])?;
        assert!(reopened.login_metadata(1001)?.is_empty());
        assert!(reopened.load_login(&id, 1001)?.verified);
        reopened.set_synced_inventory(1001, vec![id.clone()])?;
        assert_eq!(reopened.login_metadata(1001)?.len(), 1);
        assert!(reopened.login_state(&id, 1001)?.staged.is_none());
        // A passkey must not capture a login's ID in either creation path.
        let context = super::super::test_support::context()?;
        let transaction = Uuid::parse_str(&id).map_err(|_| Error::Security("test UUID".into()))?;
        assert!(
            reopened
                .prepare_registration(1001, transaction, &context, || panic!(
                    "must refuse before CREATE"
                ))
                .is_err()
        );
        let mut binding = super::super::test_support::binding(&context);
        binding.transaction = transaction;
        assert!(
            reopened
                .prepare_synced_registration(&binding, &context)
                .is_err()
        );
        // Stage an update, preserving the eligible old revision until verification.
        item.password = "updated synthetic secret".into();
        item.modified_at = 3.0;
        assert_eq!(
            reopened.import_login(1001, LoginImport::seal(1001, &recipient, 1, &item)?)?,
            2
        );
        assert_eq!(reopened.login_metadata(1001)?[0].revision, 1);
        assert!(reopened.discard_staged_login(&id, 1001, 1).is_err());
        let next = reopened.login_verification_record(&id, 1001)?;
        validate(&next)?;
        reopened.commit_verified_login(&next)?;
        assert!(reopened.check_current_login(&active).is_err());
        // Simulate a crash after active commit and before pending-file cleanup.
        reopened.write_login(&next, true)?;
        reopened.commit_verified_login(&next)?;
        assert_eq!(reopened.load_login(&id, 1001)?.revision, 2);
        assert!(reopened.login_state(&id, 1001)?.staged.is_none());
        assert!(
            reopened
                .import_login(1001, LoginImport::seal(1001, &recipient, 1, &item)?)
                .is_err()
        );
        assert_eq!(
            reopened.import_login(1001, LoginImport::seal(1001, &recipient, 2, &item)?)?,
            3
        );
        let pending = reopened.login_verification_record(&id, 1001)?;
        std::fs::remove_file(reopened.login_path(&id, false)?)
            .map_err(|e| Error::io("test remove active", e))?;
        assert!(reopened.commit_verified_login(&pending).is_err());
        reopened.discard_staged_login(&id, 1001, 3)?;
        assert!(reopened.load_login(&id, 1001).is_err());
        assert!(
            reopened
                .import_login(1001, LoginImport::seal(1001, &recipient, 2, &item)?)
                .is_err()
        );
        // Login envelopes use a distinct metadata purpose, even with the same root.
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&next)?);
        let wrong = reopened.backend.seal(Purpose::Vault, &plain)?;
        atomic_write_private(&reopened.login_path(&id, false)?, &wrong)?;
        assert!(reopened.load_login(&id, 1001).is_err());
        let paths = AppPaths::new(
            directory.path().join("config"),
            directory.path().join("state"),
            directory.path().join("runtime"),
        )?;
        let root = paths.software_key_file();
        std::fs::remove_file(&root).map_err(|e| Error::io(&root, e))?;
        assert!(Registry::open(directory.path()).is_err());
        assert!(reopened.item_recipient().is_err());
        assert!(!root.exists());
        Ok(())
    }
}
