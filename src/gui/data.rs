//! Metadata-only desktop model and selected-field reveal; no UI entities.
use crate::broker::login::{LoginMetadata, RevealField, RevealedLogin};
use crate::config::Config;
use crate::model::PasskeyProvenance;
use crate::paths::AppPaths;
use crate::security::backend_for_config;
use crate::store::StateStore;
use crate::{Error, Result};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    All,
    Passwords,
    Passkeys,
    Codes,
}
impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Passwords => "Passwords",
            Self::Passkeys => "Passkeys",
            Self::Codes => "Codes",
        }
    }
    pub fn contains(self, item: &Item) -> bool {
        match self {
            Self::All => true,
            Self::Passwords => item.login.is_some(),
            Self::Passkeys => item.login.is_none(),
            Self::Codes => item.login.as_ref().is_some_and(|l| l.has_totp),
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct Item {
    pub id: String,
    pub title: String,
    pub domain: String,
    pub username: String,
    pub storage: &'static str,
    pub protection: &'static str,
    pub login: Option<LoginMetadata>,
    pub route: Option<crate::config::LoginRoute>,
}
impl Item {
    pub fn matches(&self, category: Category, query: &str) -> bool {
        category.contains(self)
            && [&self.title, &self.domain, &self.username, &self.id]
                .iter()
                .any(|v| v.to_lowercase().contains(query))
    }
}
pub fn load_items() -> Result<Vec<Item>> {
    let paths = AppPaths::discover()?;
    let config = Config::load(&paths)?;
    let backend = backend_for_config(&config, &paths)?;
    let store = StateStore::new(&paths, backend.as_ref());
    items_from(&config, &store)
}
fn items_from(config: &Config, store: &StateStore<'_>) -> Result<Vec<Item>> {
    let index = crate::inventory::visible_index(config, store)?;
    let mut items = Vec::new();
    for login in index.credentials {
        let route = config
            .protected_logins
            .iter()
            .find(|route| route.id == login.id)
            .cloned();
        items.push(Item {
            id: login.id.clone(),
            title: if login.title.is_empty() {
                login.domain.clone()
            } else {
                login.title.clone()
            },
            domain: login.domain.clone(),
            username: login.username.clone(),
            storage: if route.is_some() {
                "Protected local copy"
            } else {
                "iCloud-synced"
            },
            protection: if route.is_some() {
                "Fingerprint required"
            } else {
                "Software-encrypted cache"
            },
            login: Some(login),
            route,
        });
    }
    for passkey in index.passkeys {
        items.push(Item {
            id: passkey.id.clone(),
            title: passkey.rp_id.clone(),
            domain: passkey.rp_id.clone(),
            username: passkey.username.clone(),
            storage: match passkey.provenance {
                PasskeyProvenance::Synced => "iCloud-synced",
                PasskeyProvenance::DeviceBound => "This device only",
            },
            protection: match passkey.signing_key.backend_id.as_str() {
                "sep-protected-software-v1" => "Fingerprint required · protected synced key",
                "sep-native-v1" => "Fingerprint required · Secure Enclave",
                "software-file-v1" => "Software-encrypted key",
                _ => "Unrecognized key protection",
            },
            login: None,
            route: None,
        });
    }
    items.sort_by_key(|item| {
        (
            item.title.to_lowercase(),
            item.username.to_lowercase(),
            item.id.clone(),
        )
    });
    Ok(items)
}
pub fn reveal_field(
    selected: &Item,
    field: RevealField,
    canceled: Arc<AtomicBool>,
) -> Result<RevealedLogin> {
    let paths = AppPaths::discover()?;
    let _lock = crate::paths::StateLock::acquire(&paths)?;
    let config = Config::load(&paths)?;
    let backend = backend_for_config(&config, &paths)?;
    let store = StateStore::new(&paths, backend.as_ref());
    reveal_from(selected, field, canceled, &config, &store)
}
fn reveal_from(
    selected: &Item,
    field: RevealField,
    canceled: Arc<AtomicBool>,
    config: &Config,
    store: &StateStore<'_>,
) -> Result<RevealedLogin> {
    if selected.login.is_none() || field == RevealField::All {
        return Err(Error::Refused("select one login field to reveal".into()));
    }
    // Freeze the exact selected metadata and route, never just a short ID.
    let current = items_from(config, store)?
        .into_iter()
        .find(|item| item.id == selected.id);
    if current.as_ref() != Some(selected) || canceled.load(Ordering::Acquire) {
        return Err(Error::Refused(
            "selection changed; refresh and select the item again".into(),
        ));
    }
    if let Some(route) = &selected.route {
        if !config.protected_logins.contains(route) {
            return Err(Error::Refused("protection route changed".into()));
        }
        return crate::broker::login::reveal(
            config
                .credential_broker
                .as_deref()
                .ok_or_else(|| Error::Config("protected login requires its broker".into()))?,
            &crate::broker::login::LoginSelection {
                id: route.id.clone(),
                revision: route.revision,
                content_binding: route.content_binding.clone(),
            },
            field,
            canceled,
        );
    }
    if config
        .protected_logins
        .iter()
        .any(|route| route.id == selected.id)
    {
        return Err(Error::Refused("protection route changed".into()));
    }
    let vault = store
        .load_vault()?
        .ok_or_else(|| Error::Refused("cache is missing".into()))?;
    let login = vault
        .credentials
        .iter()
        .find(|item| item.id == selected.id)
        .ok_or_else(|| Error::Refused("login is missing".into()))?;
    if login.protected
        || selected.login.as_ref() != Some(&LoginMetadata::from(login))
        || canceled.load(Ordering::Acquire)
    {
        return Err(Error::Refused(
            "login changed or requires its broker".into(),
        ));
    }
    let now = now();
    Ok(RevealedLogin {
        id: login.id.clone(),
        revision: 0,
        password: if field == RevealField::Password {
            Some(zeroize::Zeroizing::new(login.password.clone()))
        } else {
            None
        },
        notes: if field == RevealField::Notes {
            Some(zeroize::Zeroizing::new(login.notes.clone()))
        } else {
            None
        },
        totp: if field == RevealField::Totp {
            Some(
                crate::totp::generate(&login.totp_uri, now).ok_or_else(|| {
                    Error::InvalidData("could not generate verification code".into())
                })?,
            )
        } else {
            None
        },
    })
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{Category, Item};
    #[test]
    fn search_and_categories_do_not_need_secret_fields() {
        let item = Item {
            id: "id".into(),
            title: "Example".into(),
            domain: "example.com".into(),
            username: "Alice".into(),
            storage: "This device only",
            protection: "Fingerprint required",
            login: None,
            route: None,
        };
        assert!(item.matches(Category::All, "alice"));
        assert!(item.matches(Category::Passkeys, "example.com"));
        assert!(!item.matches(Category::Passwords, ""));
        assert!(!item.matches(Category::Codes, ""));
    }
    #[test]
    fn selected_reveal_checks_metadata_and_never_returns_other_fields() -> crate::Result<()> {
        use super::*;
        let dir = tempfile::tempdir().map_err(|e| Error::io("test", e))?;
        let paths = AppPaths::for_test(dir.path())?;
        let backend = crate::security::SoftwareFileBackend::new(paths.clone());
        let store = StateStore::new(&paths, &backend);
        let config = Config::default();
        let login = crate::model::Credential {
            protected: false,
            id: uuid::Uuid::new_v4().to_string(),
            domain: "example.com".into(),
            username: "alice".into(),
            password: "synthetic-password".into(),
            notes: "synthetic-notes".into(),
            title: "Example".into(),
            modified_at: 1.,
            last_used: 0.,
            totp_uri: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP".into(),
        };
        let mut vault = crate::model::VaultState {
            schema_version: 1,
            synced_at: 1,
            credentials: vec![login],
            passkeys: vec![],
        };
        store.save_vault(&vault)?;
        let selected = items_from(&config, &store)?.remove(0);
        let cancel = || Arc::new(AtomicBool::new(false));
        let password = reveal_from(&selected, RevealField::Password, cancel(), &config, &store)?;
        assert_eq!(
            password.password.as_deref().map(|s| s.as_str()),
            Some("synthetic-password")
        );
        assert!(password.notes.is_none() && password.totp.is_none());
        let code = reveal_from(&selected, RevealField::Totp, cancel(), &config, &store)?;
        assert!(code.totp.is_some() && code.password.is_none() && code.notes.is_none());
        assert!(!serde_json::to_string(&code)?.contains("JBSWY3DPEHPK3PXP"));
        let notes = reveal_from(&selected, RevealField::Notes, cancel(), &config, &store)?;
        assert!(notes.password.is_none() && notes.totp.is_none());
        assert!(
            reveal_from(
                &selected,
                RevealField::Password,
                Arc::new(AtomicBool::new(true)),
                &config,
                &store
            )
            .is_err()
        );
        vault.credentials[0].username = "different-account".into();
        store.save_vault(&vault)?;
        assert!(reveal_from(&selected, RevealField::Password, cancel(), &config, &store).is_err());
        // Protected snapshot with missing routing must fail before any software reveal.
        vault.credentials[0].protected = true;
        store.save_vault(&vault)?;
        assert!(items_from(&config, &store).is_err());
        assert!(reveal_from(&selected, RevealField::Password, cancel(), &config, &store).is_err());
        Ok(())
    }
}
