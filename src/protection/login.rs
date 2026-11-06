//! Explicit login migration. The source remains in an encrypted recovery journal;
//! routing commits before clearing the primary cache. Never silently re-import.
use crate::broker::{
    Operation,
    login::{LoginImport, LoginMetadata},
    registry::{LoginState, LoginSummary, Recipient},
};
use crate::config::{Config, LoginRoute};
use crate::model::Credential;
use crate::paths::{AppPaths, atomic_write_private, read_bounded};
use crate::security::{Purpose, SecurityBackend};
use crate::store::StateStore;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Prepared,
    BrokerVerified,
    Committed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    owner: u32,
    socket: PathBuf,
    account_fingerprint: String,
    source: Credential,
    prepared: LoginImport,
    phase: Phase,
}
fn path(paths: &AppPaths, id: &str) -> Result<PathBuf> {
    crate::paths::validate_record_id(id)?;
    Ok(paths.protection_dir().join(format!("login-{id}.enc")))
}
fn save(path: &Path, backend: &dyn SecurityBackend, journal: &Journal) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(journal)?);
    atomic_write_private(path, &backend.seal(Purpose::ProtectionMigration, &bytes)?)
}
fn validate_summary(journal: &Journal, summary: &LoginSummary) -> Result<()> {
    if summary.metadata != journal.prepared.metadata
        || summary.recipient_id != journal.prepared.recipient_id
        || summary.content_binding != journal.prepared.content_binding
        || journal.prepared.expected_revision.checked_add(1) != Some(summary.revision)
    {
        return Err(Error::Security(
            "broker login does not match the frozen migration source".into(),
        ));
    }
    Ok(())
}

struct SourceIdentity<'a> {
    owner: u32,
    fingerprint: &'a str,
}

/// Caller holds StateLock. Retains the encrypted recovery source; performs no
/// Apple request or recovery-copy retirement.
pub fn migrate_login(
    paths: &AppPaths,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
    id: &str,
    socket: &Path,
) -> Result<super::MigrationOutcome> {
    keychain_sep_driver::memory::make_process_nondumpable()
        .map_err(|e| Error::io("login migration memory protection", e))?;
    let account = store.load_account()?.ok_or_else(|| {
        Error::AuthenticationRequired("the source account identity is missing".into())
    })?;
    let fingerprint = crate::apple::octagon::account_fingerprint(&account);
    migrate_with(
        paths,
        backend,
        store,
        id,
        socket,
        SourceIdentity {
            owner: keychain_sep_driver::peer::effective_uid(),
            fingerprint: &fingerprint,
        },
        |operation| crate::broker::call(socket, operation),
    )
}
fn migrate_with(
    paths: &AppPaths,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
    id: &str,
    socket: &Path,
    identity: SourceIdentity<'_>,
    mut call: impl FnMut(Operation) -> Result<serde_json::Value>,
) -> Result<super::MigrationOutcome> {
    if !socket.is_absolute() {
        return Err(Error::Config("broker socket must be absolute".into()));
    }
    let owner = identity.owner;
    let fingerprint = identity.fingerprint;
    let mut config = Config::load(paths)?;
    if config
        .credential_broker
        .as_ref()
        .is_some_and(|previous| previous != socket)
    {
        return Err(Error::Refused(
            "a different credential broker is already configured".into(),
        ));
    }
    if config
        .protected_logins
        .iter()
        .any(|route| route.id == id && route.account_fingerprint != fingerprint)
    {
        return Err(Error::Refused(
            "this login belongs to a different account".into(),
        ));
    }
    let journal_path = path(paths, id)?;
    let mut vault = store
        .load_vault()?
        .ok_or_else(|| Error::Config("vault is empty".into()))?;
    let selected = vault
        .credentials
        .iter()
        .position(|item| item.id == id)
        .ok_or_else(|| Error::Refused("selected login is not in the local cache".into()))?;
    let mut journal = if journal_path
        .try_exists()
        .map_err(|e| Error::io(&journal_path, e))?
    {
        let sealed = read_bounded(&journal_path)?;
        if sealed.len() > 65536 {
            return Err(Error::InvalidData(
                "login migration journal exceeds limit".into(),
            ));
        }
        let bytes = backend.open(Purpose::ProtectionMigration, &sealed)?;
        let journal: Journal = serde_json::from_slice(&bytes)?;
        if journal.version != 1
            || journal.owner != owner
            || journal.socket != socket
            || journal.account_fingerprint != fingerprint
            || journal.source.id != id
            || journal.prepared.metadata != LoginMetadata::from_credential(&journal.source)?
            || journal.prepared.expected_revision != 0
            || journal.prepared.content_binding.len() != 64
        {
            return Err(Error::Security(
                "login migration journal identity/policy mismatch".into(),
            ));
        }
        journal
    } else {
        if vault.credentials[selected].protected {
            return Err(Error::Refused(
                "protected login recovery journal is missing; refusing replacement".into(),
            ));
        }
        if config.protected_logins.iter().any(|route| route.id == id) {
            return Err(Error::Refused(
                "committed login recovery journal is missing; refusing replacement".into(),
            ));
        }
        let state: LoginState =
            serde_json::from_value(call(Operation::LoginProtectionState { record: id.into() })?)?;
        if state.active.is_some() || state.staged.is_some() {
            return Err(Error::Refused(
                "broker already has this login without its source journal; refusing replacement"
                    .into(),
            ));
        }
        let recipient: Recipient = serde_json::from_value(call(Operation::ItemRecipient)?)?;
        let source = vault.credentials[selected].clone();
        let prepared = LoginImport::seal(owner, &recipient, 0, &source)?;
        let journal = Journal {
            version: 1,
            owner,
            socket: socket.into(),
            account_fingerprint: fingerprint.into(),
            source,
            prepared,
            phase: Phase::Prepared,
        };
        save(&journal_path, backend, &journal)?;
        journal
    };
    let route = config.protected_logins.iter().find(|route| route.id == id);
    if let Some(route) = route {
        if route.recipient_id != journal.prepared.recipient_id
            || route.content_binding != journal.prepared.content_binding
            || route.revision != 1
        {
            return Err(Error::Security("committed login route changed".into()));
        }
    }
    let mut redacted = journal.source.clone();
    redacted.protected = true;
    redacted.password.zeroize();
    redacted.notes.zeroize();
    redacted.totp_uri.zeroize();
    if vault.credentials[selected] != journal.source
        && (journal.phase == Phase::Prepared || vault.credentials[selected] != redacted)
    {
        return Err(Error::Refused(
            "source login changed during migration".into(),
        ));
    }
    let state: LoginState =
        serde_json::from_value(call(Operation::LoginProtectionState { record: id.into() })?)?;
    for summary in [&state.active, &state.staged].into_iter().flatten() {
        validate_summary(&journal, summary)?;
    }
    if state.active.is_none() && state.staged.is_none() {
        if journal.phase != Phase::Prepared || route.is_some() {
            return Err(Error::Refused(
                "previously verified login is missing; refusing replacement".into(),
            ));
        }
        call(Operation::ImportLogin {
            import: Box::new(journal.prepared.clone()),
        })?;
    }
    let verified = call(Operation::VerifyLogin { record: id.into() })?;
    let state: LoginState =
        serde_json::from_value(call(Operation::LoginProtectionState { record: id.into() })?)?;
    let active = state
        .active
        .ok_or_else(|| Error::Security("verified broker login is missing".into()))?;
    validate_summary(&journal, &active)?;
    if !active.verified
        || state.staged.is_some()
        || verified
            .get("verified")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || verified.get("revision").and_then(serde_json::Value::as_u64) != Some(active.revision)
    {
        return Err(Error::Security(
            "broker did not confirm the selected login verification".into(),
        ));
    }
    journal.phase = Phase::BrokerVerified;
    save(&journal_path, backend, &journal)?;
    let route = LoginRoute {
        id: id.into(),
        account_fingerprint: fingerprint.into(),
        recipient_id: active.recipient_id,
        revision: active.revision,
        content_binding: active.content_binding,
    };
    route.validate()?;
    if let Some(previous) = config
        .protected_logins
        .iter_mut()
        .find(|route| route.id == id)
    {
        *previous = route;
    } else {
        config.protected_logins.push(route);
    }
    config.credential_broker = Some(socket.into());
    // No-fallback policy is durable BEFORE any source fields are cleared. A
    // crash here can retain an extra software copy but cannot route normal show
    // to it. The encrypted journal keeps the explicit recovery representation.
    config.save(paths)?;
    vault.credentials[selected].protected = true;
    vault.credentials[selected].password.zeroize();
    vault.credentials[selected].notes.zeroize();
    vault.credentials[selected].totp_uri.zeroize();
    store.save_vault(&vault)?;
    journal.phase = Phase::Committed;
    save(&journal_path, backend, &journal)?;
    Ok(super::MigrationOutcome {
        record: id.into(),
        revision: active.revision,
        source_retained: true,
    })
}

/// Reconcile a complete read snapshot without restoring protected source
/// fields to the primary cache. Changed content requires an explicit verified
/// update; until that flow is connected, reject the snapshot before mutation.
pub fn reconcile_synced(
    incoming: Vec<Credential>,
    previous: &[Credential],
    config: &Config,
    paths: &AppPaths,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
) -> Result<(Vec<Credential>, Vec<String>)> {
    require_routes(previous, config)?;
    if config.protected_logins.is_empty() {
        return Ok((incoming, vec![]));
    }
    let account = store.load_account()?.ok_or_else(|| {
        Error::AuthenticationRequired("protected login sync requires its account identity".into())
    })?;
    let fingerprint = crate::apple::octagon::account_fingerprint(&account);
    let socket = config
        .credential_broker
        .as_ref()
        .ok_or_else(|| Error::Config("protected logins require their credential broker".into()))?;
    reconcile_with(incoming, config, &fingerprint, |id| {
        let state: LoginState = serde_json::from_value(crate::broker::call(
            socket,
            Operation::LoginProtectionState { record: id.into() },
        )?)?;
        let journal_path = path(paths, id)?;
        let sealed = read_bounded(&journal_path)?;
        if sealed.len() > 65536 {
            return Err(Error::InvalidData(
                "login migration journal exceeds limit".into(),
            ));
        }
        let plain = backend.open(Purpose::ProtectionMigration, &sealed)?;
        let journal: Journal = serde_json::from_slice(&plain)?;
        if journal.version != 1
            || journal.owner != keychain_sep_driver::peer::effective_uid()
            || journal.account_fingerprint != fingerprint
            || journal.socket != *socket
            || journal.source.id != id
            || journal.phase == Phase::Prepared
        {
            return Err(Error::Security(
                "protected login journal identity mismatch".into(),
            ));
        }
        Ok((
            state,
            journal.source.clone(),
            journal.prepared.content_binding.clone(),
        ))
    })
}
fn require_routes(previous: &[Credential], config: &Config) -> Result<()> {
    if previous.iter().any(|item| {
        item.protected
            && !config
                .protected_logins
                .iter()
                .any(|route| route.id == item.id)
    }) {
        return Err(Error::Refused(
            "protected login routing is missing; refusing software fallback".into(),
        ));
    }
    Ok(())
}
fn reconcile_with(
    incoming: Vec<Credential>,
    config: &Config,
    fingerprint: &str,
    mut state: impl FnMut(&str) -> Result<(LoginState, Credential, String)>,
) -> Result<(Vec<Credential>, Vec<String>)> {
    let mut result = Vec::new();
    let mut managed = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for mut item in incoming {
        if !seen.insert(item.id.clone()) {
            return Err(Error::InvalidData("duplicate synced login record".into()));
        }
        if let Some(route) = config
            .protected_logins
            .iter()
            .find(|route| route.id == item.id)
        {
            if route.account_fingerprint != fingerprint {
                return Err(Error::Refused(
                    "synced login belongs to a different protected account".into(),
                ));
            }
            let (state, source, expected_content) = state(&item.id)?;
            let active = state.active.ok_or_else(|| {
                Error::Refused("protected login is missing; refusing software fallback".into())
            })?;
            if item != source
                || expected_content != route.content_binding
                || !route.matches(&active)
                || state.staged.is_some()
                || active.metadata != LoginMetadata::from_credential(&item)?
            {
                return Err(Error::Refused(
                    "protected login update requires verification; cached items retained".into(),
                ));
            }
            managed.push(item.id.clone());
            item.protected = true;
            item.password.zeroize();
            item.notes.zeroize();
            item.totp_uri.zeroize();
        }
        result.push(item);
    }
    Ok((result, managed))
}

/// Validate the configured routing against broker metadata only. Missing,
/// disabled or changed records fail closed; never consult a recovery secret.
pub fn inventory(config: &Config) -> Result<Vec<LoginSummary>> {
    if config.protected_logins.is_empty() {
        return Ok(vec![]);
    }
    let socket = config
        .credential_broker
        .as_ref()
        .ok_or_else(|| Error::Config("protected logins require their credential broker".into()))?;
    let summaries: Vec<LoginSummary> =
        serde_json::from_value(crate::broker::call(socket, Operation::ListLogins)?)?;
    validate_inventory(config, summaries)
}
fn validate_inventory(config: &Config, summaries: Vec<LoginSummary>) -> Result<Vec<LoginSummary>> {
    let mut visible = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for summary in summaries {
        if !seen.insert(summary.metadata.id.clone()) {
            return Err(Error::Security("duplicate broker login".into()));
        }
        if let Some(route) = config
            .protected_logins
            .iter()
            .find(|route| route.id == summary.metadata.id)
        {
            if !route.matches(&summary) {
                return Err(Error::Refused(
                    "protected login changed; refusing software fallback".into(),
                ));
            }
            visible.push(summary);
        }
    }
    Ok(visible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::login::tests::{item, recipient};
    use crate::model::VaultState;
    use crate::security::SoftwareFileBackend;
    use crate::security::sep::ProviderError;
    use base64::{Engine, engine::general_purpose::STANDARD};

    struct Fixture {
        _directory: tempfile::TempDir,
        paths: AppPaths,
        backend: SoftwareFileBackend,
        source: Credential,
        fingerprint: String,
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let directory = tempfile::tempdir().map_err(|e| Error::io("test", e))?;
            let paths = AppPaths::for_test(directory.path())?;
            let backend = SoftwareFileBackend::new(paths.clone());
            let source = item();
            StateStore::new(&paths, &backend).save_vault(&VaultState {
                schema_version: 1,
                synced_at: 1,
                credentials: vec![source.clone()],
                passkeys: vec![],
            })?;
            Ok(Self {
                _directory: directory,
                paths,
                backend,
                source,
                fingerprint: format!("SHA256:{}", STANDARD.encode([1u8; 32])),
            })
        }
        fn run(&self, remote: &mut Remote) -> Result<super::super::MigrationOutcome> {
            migrate_with(
                &self.paths,
                &self.backend,
                &StateStore::new(&self.paths, &self.backend),
                &self.source.id,
                Path::new("/run/keychain/synthetic.sock"),
                SourceIdentity {
                    owner: 1001,
                    fingerprint: &self.fingerprint,
                },
                |op| remote.call(op),
            )
        }
        fn cached(&self) -> Result<Credential> {
            Ok(StateStore::new(&self.paths, &self.backend)
                .load_vault()?
                .ok_or_else(|| Error::Security("missing test cache".into()))?
                .credentials[0]
                .clone())
        }
        fn journal(&self) -> Result<Journal> {
            let data = read_bounded(&path(&self.paths, &self.source.id)?)?;
            Ok(serde_json::from_slice(
                &self.backend.open(Purpose::ProtectionMigration, &data)?,
            )?)
        }
    }
    struct Remote {
        state: LoginState,
        recipient: Recipient,
        imports: usize,
        verifies: usize,
        lose_stage: bool,
        lose_verify: bool,
        fail_config: Option<PathBuf>,
        fail_index: Option<PathBuf>,
    }
    impl Remote {
        fn new() -> Result<Self> {
            Ok(Self {
                state: LoginState {
                    active: None,
                    staged: None,
                },
                recipient: recipient()?,
                imports: 0,
                verifies: 0,
                lose_stage: false,
                lose_verify: false,
                fail_config: None,
                fail_index: None,
            })
        }
        fn call(&mut self, operation: Operation) -> Result<serde_json::Value> {
            match operation {
                Operation::LoginProtectionState { .. } => Ok(serde_json::to_value(&self.state)?),
                Operation::ItemRecipient => Ok(serde_json::to_value(&self.recipient)?),
                Operation::ImportLogin { import } => {
                    self.imports += 1;
                    self.state.staged = Some(LoginSummary {
                        metadata: import.metadata,
                        content_binding: import.content_binding,
                        recipient_id: import.recipient_id,
                        revision: import.expected_revision + 1,
                        verified: false,
                    });
                    if std::mem::take(&mut self.lose_stage) {
                        return Err(ProviderError::AmbiguousCompletion.into());
                    }
                    Ok(serde_json::json!({"revision":1,"verified":false}))
                }
                Operation::VerifyLogin { .. } => {
                    self.verifies += 1;
                    if let Some(mut staged) = self.state.staged.take() {
                        staged.verified = true;
                        self.state.active = Some(staged);
                    }
                    if std::mem::take(&mut self.lose_verify) {
                        return Err(ProviderError::AmbiguousCompletion.into());
                    }
                    if let Some(file) = self.fail_config.take() {
                        std::fs::create_dir(&file).map_err(|e| Error::io(file, e))?;
                    }
                    if let Some(file) = self.fail_index.take() {
                        std::fs::remove_file(&file).map_err(|e| Error::io(&file, e))?;
                        std::fs::create_dir(&file).map_err(|e| Error::io(file, e))?;
                    }
                    Ok(serde_json::json!({"revision":1,"verified":true}))
                }
                _ => panic!("unexpected synthetic login operation"),
            }
        }
    }
    #[test]
    fn migration_resumes_lost_stage_and_keeps_exact_content_and_recovery_source() -> Result<()> {
        let f = Fixture::new()?;
        let mut remote = Remote::new()?;
        remote.lose_stage = true;
        assert!(f.run(&mut remote).is_err());
        assert_eq!(f.cached()?, f.source);
        assert_eq!(remote.imports, 1);
        assert_eq!(remote.verifies, 0);
        let frozen = f.journal()?.prepared.content_binding;
        let outcome = f.run(&mut remote)?;
        assert!(outcome.source_retained);
        assert_eq!(remote.imports, 1);
        assert_eq!(f.journal()?.prepared.content_binding, frozen);
        assert_eq!(f.journal()?.source, f.source);
        assert!(f.journal()?.phase == Phase::Committed);
        let cached = f.cached()?;
        assert!(
            cached.password.is_empty() && cached.notes.is_empty() && cached.totp_uri.is_empty()
        );
        let config = Config::load(&f.paths)?;
        assert_eq!(config.protected_logins.len(), 1);
        assert!(
            config.protected_logins[0].matches(
                remote
                    .state
                    .active
                    .as_ref()
                    .ok_or_else(|| Error::Security("test active".into()))?
            )
        );
        let encoded = std::fs::read_to_string(f.paths.config_file())
            .map_err(|e| Error::io("test config", e))?;
        assert!(!encoded.contains(&f.source.password));
        assert!(!encoded.contains(&f.source.username));
        assert!(!encoded.contains(&f.source.totp_uri));
        Ok(())
    }
    #[test]
    fn migration_resumes_lost_verification_and_refuses_missing_committed_state() -> Result<()> {
        let f = Fixture::new()?;
        let mut remote = Remote::new()?;
        remote.lose_verify = true;
        assert!(f.run(&mut remote).is_err());
        assert_eq!(f.cached()?, f.source);
        f.run(&mut remote)?;
        assert_eq!(remote.imports, 1);
        remote.state.active = None;
        assert!(f.run(&mut remote).is_err());
        assert_eq!(remote.imports, 1);
        Ok(())
    }
    #[test]
    fn content_substitution_or_source_changes_refuse_before_verification() -> Result<()> {
        let f = Fixture::new()?;
        let mut remote = Remote::new()?;
        remote.lose_stage = true;
        assert!(f.run(&mut remote).is_err());
        let original = remote
            .state
            .staged
            .clone()
            .ok_or_else(|| Error::Security("test staged".into()))?;
        remote
            .state
            .staged
            .as_mut()
            .ok_or_else(|| Error::Security("test staged".into()))?
            .content_binding = "a".repeat(64);
        assert!(f.run(&mut remote).is_err());
        assert_eq!(remote.verifies, 0);
        remote.state.staged = Some(original);
        let mut changed = f.source.clone();
        changed.password = "different secret with identical public metadata".into();
        StateStore::new(&f.paths, &f.backend).save_vault(&VaultState {
            schema_version: 1,
            synced_at: 2,
            credentials: vec![changed],
            passkeys: vec![],
        })?;
        assert!(f.run(&mut remote).is_err());
        assert_eq!(remote.verifies, 0);
        Ok(())
    }
    #[test]
    fn config_and_index_failures_resume_without_loss_or_software_routing() -> Result<()> {
        for fail_index in [false, true] {
            let f = Fixture::new()?;
            let mut remote = Remote::new()?;
            let failure = if fail_index {
                let file = f.paths.vault_index_file();
                remote.fail_index = Some(file.clone());
                file
            } else {
                let file = f.paths.config_file();
                remote.fail_config = Some(file.clone());
                file
            };
            assert!(f.run(&mut remote).is_err());
            assert_eq!(f.journal()?.source, f.source);
            if fail_index {
                assert_eq!(Config::load(&f.paths)?.protected_logins.len(), 1);
                assert!(f.cached()?.password.is_empty());
            } else {
                assert_eq!(f.cached()?, f.source);
            }
            std::fs::remove_dir(&failure).map_err(|e| Error::io(failure, e))?;
            f.run(&mut remote)?;
            assert!(f.cached()?.password.is_empty());
            assert_eq!(remote.imports, 1);
            assert!(
                StateStore::new(&f.paths, &f.backend)
                    .load_index()?
                    .is_some()
            );
        }
        Ok(())
    }
    #[test]
    fn lost_config_is_refused_by_markers_and_only_explicit_resume_restores_it() -> Result<()> {
        let f = Fixture::new()?;
        let mut remote = Remote::new()?;
        f.run(&mut remote)?;
        let cached = f.cached()?;
        assert!(cached.protected);
        assert!(
            StateStore::new(&f.paths, &f.backend)
                .load_index()?
                .ok_or_else(|| Error::Security("test index".into()))?
                .protected_login_ids
                .contains(&f.source.id)
        );
        std::fs::remove_file(f.paths.config_file()).map_err(|e| Error::io("test config", e))?;
        assert!(require_routes(std::slice::from_ref(&cached), &Config::default()).is_err());
        f.run(&mut remote)?;
        assert_eq!(remote.imports, 1);
        assert_eq!(Config::load(&f.paths)?.protected_logins.len(), 1);
        std::fs::remove_file(f.paths.config_file()).map_err(|e| Error::io("test config", e))?;
        std::fs::remove_file(path(&f.paths, &f.source.id)?)
            .map_err(|e| Error::io("test journal", e))?;
        remote.state.active = None;
        assert!(f.run(&mut remote).is_err());
        assert_eq!(remote.imports, 1);
        Ok(())
    }
    #[test]
    fn sync_keeps_protected_data_redacted_and_refuses_changed_or_missing_identity() -> Result<()> {
        let f = Fixture::new()?;
        let mut remote = Remote::new()?;
        f.run(&mut remote)?;
        let config = Config::load(&f.paths)?;
        let mut ordinary = item();
        ordinary.id = uuid::Uuid::new_v4().to_string();
        let (cached, managed) = reconcile_with(
            vec![f.source.clone(), ordinary.clone()],
            &config,
            &f.fingerprint,
            |_| {
                Ok((
                    remote.state.clone(),
                    f.source.clone(),
                    f.journal()?.prepared.content_binding,
                ))
            },
        )?;
        assert!(
            cached[0].password.is_empty()
                && cached[0].notes.is_empty()
                && cached[0].totp_uri.is_empty()
        );
        assert_eq!(cached[1], ordinary);
        assert_eq!(managed, vec![f.source.id.clone()]);
        let (_, managed) = reconcile_with(vec![], &config, &f.fingerprint, |_| {
            panic!("deleted record must not unseal")
        })?;
        assert!(managed.is_empty());
        let mut changed = f.source.clone();
        changed.password.push('!');
        assert!(
            reconcile_with(vec![changed], &config, &f.fingerprint, |_| Ok((
                remote.state.clone(),
                f.source.clone(),
                f.journal()?.prepared.content_binding
            )))
            .is_err()
        );
        assert!(
            reconcile_with(
                vec![f.source.clone()],
                &config,
                "different-account",
                |_| panic!("wrong account must refuse before lookup")
            )
            .is_err()
        );
        remote.state.active = None;
        assert!(
            reconcile_with(vec![f.source.clone()], &config, &f.fingerprint, |_| Ok((
                remote.state.clone(),
                f.source.clone(),
                f.journal()?.prepared.content_binding
            )))
            .is_err()
        );
        assert!(validate_inventory(&config, vec![])?.is_empty());
        Ok(())
    }
}
