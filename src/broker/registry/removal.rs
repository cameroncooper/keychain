//! Explicit local native-record removal. A durable tombstone prevents identity
//! regeneration even if unlink/acknowledgement is interrupted. Not SEP key erase.
use super::*;
use crate::security::KeyRef;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRemoval {
    pub record: String,
    pub signing_key: KeyRef,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Removed {
    version: u32,
    owner: u32,
    selection: LocalRemoval,
}
impl Registry {
    fn removal_path(&self, id: &str) -> Result<PathBuf> {
        crate::paths::validate_record_id(id)?;
        Ok(self.directory.join(format!("removed-{id}.enc")))
    }
    fn removed(&self, id: &str) -> Result<Option<Removed>> {
        let path = self.removal_path(id)?;
        if !path.try_exists().map_err(|e| Error::io(&path, e))? {
            return Ok(None);
        }
        let bytes = read_bounded(&path)?;
        if bytes.len() > 4096 {
            return Err(Error::Security("local removal marker exceeds limit".into()));
        }
        let plain = self.backend.open(Purpose::RecordRemoval, &bytes)?;
        let removed: Removed = serde_json::from_slice(&plain)?;
        if removed.version != 1
            || removed.owner == 0
            || removed.selection.record != id
            || removed.selection.signing_key.backend_id != "sep-native-v1"
        {
            return Err(Error::Security("invalid local removal marker".into()));
        }
        crate::paths::validate_record_id(&removed.selection.signing_key.key_id)?;
        Ok(Some(removed))
    }
    pub(super) fn refuse_removed(&self, id: &str) -> Result<()> {
        if self.removed(id)?.is_some() {
            return Err(Error::Refused(
                "local credential was explicitly removed".into(),
            ));
        }
        Ok(())
    }
    pub(super) fn removed_for_owner(&self, id: &str, owner: u32) -> Result<bool> {
        match self.removed(id)? {
            Some(removed) if removed.owner == owner => Ok(true),
            Some(_) => Err(Error::Security("local removal owner mismatch".into())),
            None => Ok(false),
        }
    }
    /// Only native device-bound records: synced recovery journals and account
    /// inventory are untouched. The selected key must match exactly. A retry
    /// finishes unlinking the same record after a durable removal marker.
    pub fn remove_local(
        &self,
        owner: u32,
        selection: &LocalRemoval,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let _lock = self.update_lock()?;
        check()?;
        let path = self.directory.join(format!("{}.enc", selection.record));
        let marker = self.removal_path(&selection.record)?;
        if let Some(removed) = self.removed(&selection.record)? {
            if removed.owner != owner || removed.selection.signing_key != selection.signing_key {
                return Err(Error::Refused(
                    "removed credential selection does not match".into(),
                ));
            }
        } else {
            let record = self.load(&selection.record, owner)?;
            if record.credential.signing_key != selection.signing_key {
                return Err(Error::Refused("local credential selection changed".into()));
            }
            // The authenticated encrypted marker is published/fsynced before
            // erasing the key file. Filename/selection paths refuse it thereafter.
            let removed = Removed {
                version: 1,
                owner,
                selection: selection.clone(),
            };
            let plain = zeroize::Zeroizing::new(serde_json::to_vec(&removed)?);
            check()?;
            create_private_exclusive(&marker, &self.backend.seal(Purpose::RecordRemoval, &plain)?)?;
        }
        // A previous invocation may have failed fsync after publishing readable
        // bytes. Re-establish marker durability before deleting any wrapped key.
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&marker)
            .and_then(|file| file.sync_all())
            .map_err(|e| Error::io(&marker, e))?;
        std::fs::File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| Error::io(&self.directory, e))?;
        // Complete cleanup even if cancellation arrives after marker publication.
        // A late cancellation suppresses delivery; it cannot resurrect the key.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(&path, e)),
        }
        let intent = self
            .directory
            .join(format!("{}.pending.enc", selection.record));
        match std::fs::remove_file(&intent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(&intent, e)),
        }
        std::fs::File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| Error::io(&self.directory, e))?;
        check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::registry::test_support::context;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use std::cell::Cell;

    fn key() -> Result<StoredSepKey> {
        let secret = p256::SecretKey::from_slice(&[7; 32])
            .map_err(|_| Error::Security("synthetic key".into()))?;
        Ok(serde_json::from_value(serde_json::json!({
            "version": 1,
            "reference": KeyRef {
                backend_id:"sep-native-v1".into(),key_id:Uuid::new_v4().to_string(),
                usage:crate::security::KeyUsage::WebAuthnSigning,
                algorithm:crate::security::KeyAlgorithm::P256,
            },
            "policy":"biometry-any", "wrapped_blob":STANDARD.encode(b"synthetic wrapped blob"),
            "public_sec1":STANDARD.encode(secret.public_key().to_encoded_point(false).as_bytes()),
            "allow_decrypt":false
        }))?)
    }
    #[test]
    #[ignore = "requires root; disposable registry only; no SEP/Apple operations"]
    fn root_local_removal_survives_interruption_and_never_regenerates_the_key() -> Result<()> {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let directory = tempfile::tempdir().map_err(|e| Error::io("test", e))?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(directory.path(), e))?;
        let registry = Registry::open(directory.path())?;
        let context = context()?;
        let id = Uuid::new_v4();
        let first = registry.prepare_registration(1001, id, &context, key)?;
        registry.registration_deliverable(1001, id, &context, &first.credential.signing_key)?;
        let other_id = Uuid::new_v4();
        let other = registry.prepare_registration(1001, other_id, &context, key)?;
        registry.registration_deliverable(
            1001,
            other_id,
            &context,
            &other.credential.signing_key,
        )?;
        let selected = LocalRemoval {
            record: id.to_string(),
            signing_key: first.credential.signing_key.clone(),
        };
        let mut wrong = selected.clone();
        wrong.signing_key.key_id = Uuid::new_v4().to_string();
        assert!(registry.remove_local(1002, &selected, &|| Ok(())).is_err());
        assert!(registry.remove_local(1001, &wrong, &|| Ok(())).is_err());
        assert!(
            registry
                .remove_local(1001, &selected, &|| Err(Error::Refused(
                    "synthetic cancel".into()
                )))
                .is_err()
        );
        assert!(registry.load(&selected.record, 1001).is_ok());
        assert!(!registry.removal_path(&selected.record)?.exists());

        // Simulate durable publication followed by process loss before unlink.
        let marker = registry.removal_path(&selected.record)?;
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&Removed {
            version: 1,
            owner: 1001,
            selection: selected.clone(),
        })?);
        create_private_exclusive(
            &marker,
            &registry.backend.seal(Purpose::RecordRemoval, &plain)?,
        )?;
        drop(registry);
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(directory.path(), e))?;
        let registry = Registry::open(directory.path())?;
        assert!(directory.path().join(format!("{id}.enc")).exists());
        assert!(registry.load(&selected.record, 1001).is_err());
        assert_eq!(
            registry.browser_credentials(1001)?,
            vec![other.credential.clone()]
        );
        let created = Cell::new(false);
        assert!(
            registry
                .prepare_registration(1001, id, &context, || {
                    created.set(true);
                    key()
                })
                .is_err()
        );
        assert!(!created.get());
        assert!(registry.login_path(&selected.record, true).is_err());
        assert!(registry.remove_local(1002, &selected, &|| Ok(())).is_err());
        assert!(registry.remove_local(1001, &wrong, &|| Ok(())).is_err());
        registry.remove_local(1001, &selected, &|| Ok(()))?;
        registry.remove_local(1001, &selected, &|| Ok(()))?;
        assert!(!directory.path().join(format!("{id}.enc")).exists());
        assert!(marker.exists());
        assert_eq!(registry.browser_credentials(1001)?, vec![other.credential]);

        // Late cancellation can suppress the reply after durable removal, but
        // cannot restore eligibility or create a reusable authentication grant.
        let final_id = registry.provision_diagnostic(1001, key()?)?;
        let final_key = registry
            .load(&final_id, 1001)?
            .credential
            .signing_key
            .clone();
        let checks = Cell::new(0);
        let result = registry.remove_local(
            1001,
            &LocalRemoval {
                record: final_id.clone(),
                signing_key: final_key,
            },
            &|| {
                checks.set(checks.get() + 1);
                if checks.get() == 3 {
                    Err(Error::Refused("synthetic late cancel".into()))
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err());
        assert!(registry.load(&final_id, 1001).is_err());
        assert!(!directory.path().join(format!("{final_id}.enc")).exists());

        // Corrupt markers fail closed instead of allowing recreation.
        atomic_write_private(&marker, b"corrupt synthetic marker")?;
        assert!(registry.filename(&selected.record).is_err());
        assert!(registry.remove_local(1001, &selected, &|| Ok(())).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires root; disposable registry only; no SEP/Apple operations"]
    fn root_removal_marker_alone_prevents_metadata_root_regeneration() -> Result<()> {
        let directory = tempfile::tempdir().map_err(|e| Error::io("test", e))?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(directory.path(), e))?;
        let registry = Registry::open(directory.path())?;
        let id = registry.provision_diagnostic(1001, key()?)?;
        let signing_key = registry.load(&id, 1001)?.credential.signing_key.clone();
        registry.remove_local(
            1001,
            &LocalRemoval {
                record: id.clone(),
                signing_key,
            },
            &|| Ok(()),
        )?;
        assert!(!directory.path().join(format!("{id}.enc")).exists());
        let root = directory.path().join("state/software.key");
        std::fs::remove_file(&root).map_err(|e| Error::io(&root, e))?;
        assert!(Registry::open(directory.path()).is_err());
        assert!(!root.exists());
        Ok(())
    }
}
