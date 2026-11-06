//! Shared metadata inventory for the CLI and desktop UI. Never reveals secret fields.
use crate::config::Config;
use crate::model::{PasskeyCredential, VaultState};
use crate::store::StateStore;
use crate::{Error, Result};

pub fn visible_index(config: &Config, store: &StateStore<'_>) -> Result<crate::store::VaultIndex> {
    let mut index = match store.load_index()? {
        Some(index) => index,
        None if !store.has_vault()? => crate::store::VaultIndex {
            schema_version: 1,
            source_sha256: String::new(),
            protected_login_ids: vec![],
            credentials: vec![],
            passkeys: vec![],
        },
        None if config.protected_logins.is_empty() => crate::store::VaultIndex::from_vault(
            &store
                .load_vault()?
                .ok_or_else(|| Error::Config("vault is empty; run `keychain sync`".into()))?,
            String::new(),
        ),
        None => {
            return Err(Error::Refused(
                "protected cache metadata is missing; resume protection to repair it".into(),
            ));
        }
    };
    if index
        .protected_login_ids
        .iter()
        .any(|id| !config.protected_logins.iter().any(|route| &route.id == id))
    {
        return Err(Error::Refused(
            "protected login routing is missing; resume protection to restore it".into(),
        ));
    }
    index.credentials.retain(|item| {
        !config
            .protected_logins
            .iter()
            .any(|route| route.id == item.id)
    });
    if let Some(socket) = &config.credential_broker {
        let native: Vec<PasskeyCredential> = serde_json::from_value(crate::broker::call(
            socket,
            crate::broker::Operation::ListCredentials,
        )?)?;
        let mut metadata = VaultState {
            schema_version: 1,
            synced_at: 0,
            credentials: vec![],
            passkeys: std::mem::take(&mut index.passkeys),
        };
        merge_native_inventory(&mut metadata, native)?;
        index.passkeys = std::mem::take(&mut metadata.passkeys);
        for login in crate::protection::login::inventory(config)? {
            if index
                .passkeys
                .iter()
                .any(|item| item.id == login.metadata.id)
            {
                return Err(Error::Security("login/passkey inventory collision".into()));
            }
            index.credentials.push(login.metadata);
        }
    }
    Ok(index)
}

pub fn merge_native_inventory(
    vault: &mut VaultState,
    records: Vec<PasskeyCredential>,
) -> Result<()> {
    use crate::model::PasskeyProvenance;
    let mut seen = std::collections::BTreeSet::new();
    for record in records {
        if !seen.insert(record.id.clone()) {
            return Err(Error::Security("duplicate broker inventory record".into()));
        }
        if record.provenance != PasskeyProvenance::DeviceBound {
            continue;
        }
        if let Some(previous) = vault.passkeys.iter_mut().find(|p| p.id == record.id) {
            if previous.provenance != PasskeyProvenance::DeviceBound
                || previous.signing_key != record.signing_key
                || previous.rp_id != record.rp_id
                || previous.credential_id != record.credential_id
                || previous.user_handle != record.user_handle
            {
                return Err(Error::Security(
                    "broker native credential collides with a different local identity".into(),
                ));
            }
            *previous = record;
        } else {
            vault.passkeys.push(record);
        }
    }
    Ok(())
}
