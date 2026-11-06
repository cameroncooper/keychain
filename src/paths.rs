use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use uuid::Uuid;

use crate::{Error, Result};

pub const MAX_STATE_FILE: u64 = 64 * 1024 * 1024;

/// Preserve Apple's record-name case, accepting only the hyphenated UUID shape
/// as a single filename component. Generated local UUIDs use lowercase.
pub fn validate_record_id(id: &str) -> Result<()> {
    let parsed =
        Uuid::parse_str(id).map_err(|_| Error::InvalidData("invalid record UUID".into()))?;
    if !id.eq_ignore_ascii_case(&parsed.to_string()) {
        return Err(Error::InvalidData(
            "record UUID must use the hyphenated form".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| Error::Config("HOME is not set".into()))?;
        let config = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let state = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state"));
        let runtime = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| state.join("runtime"));
        Self::new(
            config.join("keychain"),
            state.join("keychain"),
            runtime.join("keychain"),
        )
    }

    pub fn new(config_dir: PathBuf, state_dir: PathBuf, runtime_dir: PathBuf) -> Result<Self> {
        let this = Self {
            config_dir,
            state_dir,
            runtime_dir,
        };
        this.ensure()?;
        Ok(this)
    }

    #[cfg(test)]
    pub fn for_test(root: &Path) -> Result<Self> {
        Self::new(
            root.join("config"),
            root.join("state"),
            root.join("runtime"),
        )
    }

    fn ensure(&self) -> Result<()> {
        for dir in [&self.config_dir, &self.state_dir, &self.runtime_dir] {
            fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
            let metadata = fs::symlink_metadata(dir).map_err(|e| Error::io(dir, e))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Error::Security(format!(
                    "{} must be a real directory, not a symlink",
                    dir.display()
                )));
            }
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::io(dir, e))?;
        }
        Ok(())
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn software_key_file(&self) -> PathBuf {
        self.state_dir.join("software.key")
    }
    pub fn keys_file(&self) -> PathBuf {
        self.state_dir.join("keys.enc")
    }
    pub fn account_file(&self) -> PathBuf {
        self.state_dir.join("account.enc")
    }
    pub fn device_file(&self) -> PathBuf {
        self.state_dir.join("device.enc")
    }
    pub fn octagon_file(&self) -> PathBuf {
        self.state_dir.join("octagon.enc")
    }
    pub fn trust_repair_file(&self) -> PathBuf {
        self.state_dir.join("octagon-repair.enc")
    }
    pub fn vault_file(&self) -> PathBuf {
        self.state_dir.join("vault.enc")
    }
    pub fn previous_vault_file(&self) -> PathBuf {
        self.state_dir.join("vault.previous.enc")
    }
    pub fn protection_dir(&self) -> PathBuf {
        self.state_dir.join("protection")
    }
    pub fn anisette_dir(&self) -> PathBuf {
        self.state_dir.join("anisette")
    }
    pub fn lock_file(&self) -> PathBuf {
        self.runtime_dir.join("state.lock")
    }
}

pub struct StateLock {
    file: File,
}

impl StateLock {
    pub fn acquire(paths: &AppPaths) -> Result<Self> {
        let path = paths.lock_file();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        validate_private_file(&path, &file)?;
        file.try_lock_exclusive()
            .map_err(|_| Error::Config("another keychain operation is already running".into()))?;
        Ok(Self { file })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    validate_private_file(path, &file)?;
    let meta = file.metadata().map_err(|e| Error::io(path, e))?;
    if meta.len() > MAX_STATE_FILE {
        return Err(Error::InvalidData(format!(
            "{} exceeds the {} byte state-file limit",
            path.display(),
            MAX_STATE_FILE
        )));
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_STATE_FILE + 1)
        .read_to_end(&mut data)
        .map_err(|e| Error::io(path, e))?;
    if data.len() as u64 > MAX_STATE_FILE {
        return Err(Error::InvalidData(format!(
            "{} exceeds the {} byte state-file limit",
            path.display(),
            MAX_STATE_FILE
        )));
    }
    Ok(data)
}

pub fn atomic_write_private(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Config(format!("{} has no parent", path.display())))?;
    fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    let tmp = parent.join(format!(".keychain-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .map_err(|e| Error::io(&tmp, e))?;
        file.write_all(data).map_err(|e| Error::io(&tmp, e))?;
        file.sync_all().map_err(|e| Error::io(&tmp, e))?;
        fs::rename(&tmp, path).map_err(|e| Error::io(path, e))?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| Error::io(parent, e))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn create_private_exclusive(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    file.write_all(data).map_err(|e| Error::io(path, e))?;
    file.sync_all().map_err(|e| Error::io(path, e))?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Config(format!("{} has no parent", path.display())))?;
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| Error::io(parent, e))?;
    Ok(())
}

fn validate_private_file(path: &Path, file: &File) -> Result<()> {
    let metadata = file.metadata().map_err(|e| Error::io(path, e))?;
    if !metadata.is_file() {
        return Err(Error::Security(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Security(format!(
            "{} has insecure mode {:04o}; expected no group or other access",
            path.display(),
            metadata.mode() & 0o7777
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::tempdir;

    use super::*;
    #[test]
    fn apple_record_case_is_preserved_but_unsafe_or_alternate_shapes_are_rejected() {
        for id in [
            "89B32928-CAAE-44A0-8255-AFDBD822C7EE",
            "89b32928-caae-44a0-8255-afdbd822c7ee",
        ] {
            assert!(validate_record_id(id).is_ok());
        }
        for id in [
            "../../software.key",
            "89B32928CAAE44A08255AFDBD822C7EE",
            "{89B32928-CAAE-44A0-8255-AFDBD822C7EE}",
            "89B32928-CAAE-44A0-8255-AFDBD822C7EE/extra",
        ] {
            assert!(validate_record_id(id).is_err());
        }
    }

    #[test]
    fn bounded_read_rejects_permissive_files() {
        let root = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = root.path().join("secret");
        create_private_exclusive(&path, b"secret")
            .unwrap_or_else(|error| panic!("create: {error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .unwrap_or_else(|error| panic!("chmod: {error}"));
        assert!(matches!(read_bounded(&path), Err(Error::Security(_))));
    }

    #[test]
    fn bounded_read_rejects_symlinks() {
        let root = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let target = root.path().join("target");
        let link = root.path().join("link");
        create_private_exclusive(&target, b"secret")
            .unwrap_or_else(|error| panic!("create: {error}"));
        symlink(&target, &link).unwrap_or_else(|error| panic!("symlink: {error}"));
        assert!(read_bounded(&link).is_err());
    }
}
