use std::path::PathBuf;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::paths::{AppPaths, atomic_write_private, read_bounded};
use crate::{Error, Result};

/// Non-secret durable no-fallback routing. Usernames/titles/passwords stay out
/// of config; the content tag's random MAC key stays inside the SEP envelope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoginRoute {
    pub id: String,
    pub account_fingerprint: String,
    pub recipient_id: String,
    pub revision: u64,
    pub content_binding: String,
}
impl LoginRoute {
    pub fn matches(&self, summary: &crate::broker::registry::LoginSummary) -> bool {
        summary.verified
            && summary.metadata.id == self.id
            && summary.revision == self.revision
            && summary.recipient_id == self.recipient_id
            && summary.content_binding == self.content_binding
    }
    pub fn validate(&self) -> Result<()> {
        crate::paths::validate_record_id(&self.id)?;
        crate::paths::validate_record_id(&self.recipient_id)?;
        let fingerprint = self
            .account_fingerprint
            .strip_prefix("SHA256:")
            .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok());
        if self.revision == 0
            || fingerprint.is_none_or(|bytes| bytes.len() != 32)
            || self.content_binding.len() != 64
            || hex::decode(&self.content_binding)
                .map(|bytes| hex::encode(bytes) != self.content_binding)
                .unwrap_or(true)
        {
            return Err(Error::Config("invalid protected login route".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u32,
    pub security_backend: String,
    pub anisette_helper: Option<PathBuf>,
    /// Optional selected-credential broker; independent of account-state storage.
    /// When set, browser operations must not fall back to the software vault.
    #[serde(default)]
    pub credential_broker: Option<PathBuf>,
    #[serde(default)]
    pub protected_logins: Vec<LoginRoute>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            security_backend: "software-file".into(),
            anisette_helper: None,
            credential_broker: None,
            protected_logins: vec![],
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
        config.validate_login_routes()?;
        Ok(config)
    }

    fn validate_login_routes(&self) -> Result<()> {
        if self.protected_logins.len() > 4096
            || (!self.protected_logins.is_empty() && self.credential_broker.is_none())
        {
            return Err(Error::Config(
                "protected logins require their credential broker".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for route in &self.protected_logins {
            route.validate()?;
            if !seen.insert(route.id.to_ascii_lowercase()) {
                return Err(Error::Config("duplicate protected login route".into()));
            }
        }
        Ok(())
    }
    pub fn save(&self, paths: &AppPaths) -> Result<()> {
        self.validate_login_routes()?;
        let encoded = toml::to_string_pretty(self)
            .map_err(|error| Error::Config(format!("could not encode config: {error}")))?;
        atomic_write_private(&paths.config_file(), encoded.as_bytes())
    }
}
