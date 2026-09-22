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
    pub fn save_vault(&self, value: &VaultState) -> Result<()> {
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
