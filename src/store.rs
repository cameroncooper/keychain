use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::{Zeroize, Zeroizing};

use crate::model::{AccountState, DeviceIdentity, OctagonState, VaultState};
use crate::paths::{AppPaths, atomic_write_private, read_bounded};
use crate::security::{Purpose, SecurityBackend};
use crate::{Error, Result};

pub struct StateStore<'a> {
    paths: &'a AppPaths,
    backend: &'a dyn SecurityBackend,
}

impl<'a> StateStore<'a> {
    pub fn new(paths: &'a AppPaths, backend: &'a dyn SecurityBackend) -> Self {
        Self { paths, backend }
    }

    fn save<T: Serialize>(&self, path: &Path, purpose: Purpose, value: &T) -> Result<()> {
        let mut plain = Zeroizing::new(serde_json::to_vec(value)?);
        let envelope = self.backend.seal(purpose, &plain)?;
        plain.zeroize();
        atomic_write_private(path, &envelope)
    }

    fn load<T: DeserializeOwned>(&self, path: &Path, purpose: Purpose) -> Result<Option<T>> {
        if !path.exists() {
            return Ok(None);
        }
        let envelope = read_bounded(path)?;
        let plain = self.backend.open(purpose, &envelope)?;
        Ok(Some(serde_json::from_slice(&plain)?))
    }

    pub fn save_account(&self, value: &AccountState) -> Result<()> {
        self.save(&self.paths.account_file(), Purpose::Account, value)
    }
    pub fn load_account(&self) -> Result<Option<AccountState>> {
        let state: Option<AccountState> =
            self.load(&self.paths.account_file(), Purpose::Account)?;
        validate_schema("account", state.as_ref().map(|state| state.schema_version))?;
        Ok(state)
    }
    pub fn save_device(&self, value: &DeviceIdentity) -> Result<()> {
        self.save(&self.paths.device_file(), Purpose::Device, value)
    }
    pub fn load_device(&self) -> Result<Option<DeviceIdentity>> {
        let state: Option<DeviceIdentity> =
            self.load(&self.paths.device_file(), Purpose::Device)?;
        validate_schema("device", state.as_ref().map(|state| state.schema_version))?;
        Ok(state)
    }
    pub fn save_octagon(&self, value: &OctagonState) -> Result<()> {
        self.save(&self.paths.octagon_file(), Purpose::Octagon, value)
    }
    pub fn load_octagon(&self) -> Result<Option<OctagonState>> {
        let state: Option<OctagonState> =
            self.load(&self.paths.octagon_file(), Purpose::Octagon)?;
        validate_schema("Octagon", state.as_ref().map(|state| state.schema_version))?;
        Ok(state)
    }
    pub fn save_trust_repair(&self, value: &crate::recovery::TrustRepair) -> Result<()> {
        self.save(&self.paths.trust_repair_file(), Purpose::TrustRepair, value)
    }
    pub fn load_trust_repair(&self) -> Result<Option<crate::recovery::TrustRepair>> {
        let journal: Option<crate::recovery::TrustRepair> =
            self.load(&self.paths.trust_repair_file(), Purpose::TrustRepair)?;
        if let Some(journal) = &journal {
            journal.validate()?;
        }
        Ok(journal)
    }
    pub fn save_vault(&self, value: &VaultState) -> Result<()> {
        let current = self.paths.vault_file();
        if current.try_exists().map_err(|e| Error::io(&current, e))? {
            let encrypted = read_bounded(&current)?;
            let plain = self.backend.open(Purpose::Vault, &encrypted)?;
            let previous: VaultState = serde_json::from_slice(&plain)?;
            validate_schema("vault", Some(previous.schema_version))?;
            if !previous.credentials.is_empty() || !previous.passkeys.is_empty() {
                atomic_write_private(&self.paths.previous_vault_file(), &encrypted)?;
            }
        }
        self.save(&self.paths.vault_file(), Purpose::Vault, value)
    }
    pub fn load_vault(&self) -> Result<Option<VaultState>> {
        let state: Option<VaultState> = self.load(&self.paths.vault_file(), Purpose::Vault)?;
        validate_schema("vault", state.as_ref().map(|state| state.schema_version))?;
        Ok(state)
    }

    pub fn remove_if_exists(&self, path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(path, e)),
        }
    }
}

fn validate_schema(kind: &str, version: Option<u32>) -> Result<()> {
    if let Some(version) = version {
        if version != 1 {
            return Err(Error::InvalidData(format!(
                "unsupported {kind} state version {version}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::security::SoftwareFileBackend;
    #[test]
    fn an_empty_replacement_preserves_the_last_nonempty_encrypted_snapshot() {
        let directory = tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let paths = AppPaths::for_test(directory.path()).unwrap_or_else(|e| panic!("paths: {e}"));
        let backend = SoftwareFileBackend::new(paths.clone());
        let store = StateStore::new(&paths, &backend);
        let old = VaultState {
            schema_version: 1,
            synced_at: 1,
            passkeys: vec![],
            credentials: vec![crate::model::Credential {
                id: "synthetic".into(),
                domain: "example.com".into(),
                username: "user".into(),
                password: "synthetic-secret".into(),
                title: "old".into(),
                modified_at: 0.0,
                notes: String::new(),
                last_used: 0.0,
                totp_uri: String::new(),
            }],
        };
        store
            .save_vault(&old)
            .unwrap_or_else(|e| panic!("save old: {e}"));
        let empty = VaultState {
            schema_version: 1,
            synced_at: 2,
            passkeys: vec![],
            credentials: vec![],
        };
        store
            .save_vault(&empty)
            .unwrap_or_else(|e| panic!("save empty: {e}"));
        store
            .save_vault(&empty)
            .unwrap_or_else(|e| panic!("repeat empty: {e}"));
        let previous: Option<VaultState> = store
            .load(&paths.previous_vault_file(), Purpose::Vault)
            .unwrap_or_else(|e| panic!("backup: {e}"));
        assert_eq!(previous, Some(old));
        assert_eq!(
            store
                .load_vault()
                .unwrap_or_else(|e| panic!("current: {e}")),
            Some(empty)
        );
        let bytes = read_bounded(&paths.previous_vault_file())
            .unwrap_or_else(|e| panic!("read backup: {e}"));
        assert!(
            !bytes
                .windows(b"synthetic-secret".len())
                .any(|window| window == b"synthetic-secret")
        );
    }

    #[test]
    fn vault_round_trip_and_schema_guard() {
        let root = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths =
            AppPaths::for_test(root.path()).unwrap_or_else(|error| panic!("paths: {error}"));
        let backend = SoftwareFileBackend::new(paths.clone());
        let store = StateStore::new(&paths, &backend);
        let vault = VaultState {
            schema_version: 1,
            synced_at: 123,
            credentials: Vec::new(),
            passkeys: Vec::new(),
        };
        store
            .save_vault(&vault)
            .unwrap_or_else(|error| panic!("save: {error}"));
        assert_eq!(
            store
                .load_vault()
                .unwrap_or_else(|error| panic!("load: {error}")),
            Some(vault)
        );

        store
            .save_vault(&VaultState {
                schema_version: 2,
                synced_at: 456,
                credentials: Vec::new(),
                passkeys: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("save: {error}"));
        assert!(matches!(store.load_vault(), Err(Error::InvalidData(_))));
    }
}
