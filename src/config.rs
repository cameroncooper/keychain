use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths::{AppPaths, atomic_write_private, read_bounded};
use crate::{Error, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u32,
    pub security_backend: String,
    pub anisette_helper: Option<PathBuf>,
    /// Optional selected-credential broker; independent of account-state storage.
    /// When set, browser operations must not fall back to the software vault.
    #[serde(default)]
    pub credential_broker: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            security_backend: "software-file".into(),
            anisette_helper: None,
            credential_broker: None,
        }
    }
}

impl Config {
    pub fn load(paths: &AppPaths) -> Result<Self> {
        let path = paths.config_file();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = read_bounded(&path)?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| Error::Config(format!("{} is not UTF-8", path.display())))?;
        let config: Self = toml::from_str(text).map_err(|error| {
            Error::Config(format!("could not parse {}: {error}", path.display()))
        })?;
        if config.schema_version != 1 {
            return Err(Error::Config(format!(
                "unsupported config version {}",
                config.schema_version
            )));
        }
        if config.security_backend != "software-file" {
            return Err(Error::Config(format!(
                "security backend {} is not available in this build",
                config.security_backend
            )));
        }
        if config
            .credential_broker
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(Error::Config(
                "credential_broker must be an absolute Unix socket path".into(),
            ));
        }
        Ok(config)
    }

    pub fn save(&self, paths: &AppPaths) -> Result<()> {
        let encoded = toml::to_string_pretty(self)
            .map_err(|error| Error::Config(format!("could not encode config: {error}")))?;
        atomic_write_private(&paths.config_file(), encoded.as_bytes())
    }
}
