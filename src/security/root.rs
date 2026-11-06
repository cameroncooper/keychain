use p384::elliptic_curve::rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::paths::{AppPaths, create_private_exclusive, read_bounded};
use crate::{Error, Result};

/// Supplies the encryption root. A protected implementation must never fall back
/// to a file root when authorization or hardware access fails.
pub trait RootKeySource: Send + Sync {
    fn root_key(&self) -> Result<Zeroizing<[u8; 32]>>;
}

pub struct FileRootKeySource {
    paths: AppPaths,
}

impl FileRootKeySource {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }
}

impl RootKeySource for FileRootKeySource {
    fn root_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let path = self.paths.software_key_file();
        if path.exists() {
            let bytes = Zeroizing::new(read_bounded(&path)?);
            let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                Error::Security(format!("{} is not a 32-byte root key", path.display()))
            })?;
            return Ok(Zeroizing::new(key));
        }
        if [
            self.paths.keys_file(),
            self.paths.account_file(),
            self.paths.device_file(),
            self.paths.octagon_file(),
            self.paths.trust_repair_file(),
            self.paths.vault_file(),
            self.paths.previous_vault_file(),
            self.paths.protection_dir(),
        ]
        .iter()
        .any(|p| p.exists())
        {
            return Err(Error::Security(format!(
                "{} is missing while encrypted state exists; refusing to generate a replacement",
                path.display()
            )));
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(&mut *key);
        match create_private_exclusive(&path, key.as_slice()) {
            Ok(()) => Ok(key),
            Err(_) if path.exists() => self.root_key(),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::atomic_write_private;
    use crate::security::{Purpose, SecurityBackend, SoftwareFileBackend};

    struct DeniedRoot;
    impl RootKeySource for DeniedRoot {
        fn root_key(&self) -> Result<Zeroizing<[u8; 32]>> {
            Err(Error::Refused("authorization denied".into()))
        }
    }

    #[test]
    fn denied_source_never_falls_back_to_existing_file_root() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let paths = AppPaths::for_test(dir.path()).unwrap_or_else(|e| panic!("paths: {e}"));
        let original = SoftwareFileBackend::new(paths.clone());
        let encrypted = original
            .seal(Purpose::Vault, b"existing vault")
            .unwrap_or_else(|e| panic!("seal: {e}"));
        let protected = SoftwareFileBackend::with_root_source(paths, Box::new(DeniedRoot));
        assert!(matches!(
            protected.open(Purpose::Vault, &encrypted),
            Err(Error::Refused(_))
        ));
        assert!(matches!(
            protected.seal(Purpose::Vault, b"new data"),
            Err(Error::Refused(_))
        ));
        assert_eq!(
            &*original
                .open(Purpose::Vault, &encrypted)
                .unwrap_or_else(|e| panic!("open: {e}")),
            b"existing vault"
        );
    }

    #[test]
    fn missing_root_with_existing_state_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let paths = AppPaths::for_test(dir.path()).unwrap_or_else(|e| panic!("paths: {e}"));
        atomic_write_private(&paths.vault_file(), b"existing state")
            .unwrap_or_else(|e| panic!("write: {e}"));
        let source = FileRootKeySource::new(paths.clone());
        assert!(matches!(source.root_key(), Err(Error::Security(_))));
        assert!(!paths.software_key_file().exists());
    }
    #[test]
    fn migration_journal_alone_prevents_root_regeneration() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let paths = AppPaths::for_test(dir.path()).unwrap_or_else(|e| panic!("paths: {e}"));
        atomic_write_private(
            &paths.protection_dir().join("synthetic.enc"),
            b"existing encrypted journal",
        )
        .unwrap_or_else(|e| panic!("journal: {e}"));
        assert!(FileRootKeySource::new(paths.clone()).root_key().is_err());
        assert!(!paths.software_key_file().exists());
    }
}
