//! Explicit selected-passkey migration. The local source remains as a recovery
//! copy; normal references move only after the broker verifies the same identity.
//! This module never deletes a scalar, replaces a root or performs Apple writes.
pub mod login;

use crate::broker::{
    Operation,
    registry::{ProtectedSummary, ProtectionState, Recipient},
};
use crate::config::Config;
use crate::model::{PasskeyCredential, PasskeyProvenance};
use crate::paths::{AppPaths, atomic_write_private, read_bounded};
use crate::security::{KeyAlgorithm, KeyRef, KeyUsage, Purpose, SecurityBackend};
use crate::store::StateStore;
use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
    source: PasskeyCredential,
    public_sec1: String,
    destination: Option<KeyRef>,
    revision: Option<u64>,
    phase: Phase,
}

pub struct MigrationOutcome {
    pub record: String,
    pub revision: u64,
    pub source_retained: bool,
}

/// Caller holds StateLock across this operation to exclude concurrent sync or
/// logout in the normal CLI. Interrupted calls are resumed with the same ID/path.
pub fn migrate_passkey(
    paths: &AppPaths,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
    id: &str,
    socket: &Path,
) -> Result<MigrationOutcome> {
    keychain_sep_driver::memory::make_process_nondumpable()
        .map_err(|e| Error::io("migration process memory protection", e))?;
    migrate_with(paths, backend, store, id, socket, |operation| {
        crate::broker::call(socket, operation)
    })
}

fn migration_path(paths: &AppPaths, id: &str) -> Result<PathBuf> {
    crate::paths::validate_record_id(id)?;
    let directory = paths.protection_dir();
    Ok(directory.join(format!("{id}.enc")))
}
fn save_journal(path: &Path, backend: &dyn SecurityBackend, journal: &Journal) -> Result<()> {
    let plain = zeroize::Zeroizing::new(serde_json::to_vec(journal)?);
    atomic_write_private(path, &backend.seal(Purpose::ProtectionMigration, &plain)?)
}

pub fn is_broker_key(key: &KeyRef) -> bool {
    matches!(
        key.backend_id.as_str(),
        "sep-protected-software-v1" | "sep-native-v1"
    )
}

fn expected_reference(id: &str) -> KeyRef {
    KeyRef {
        backend_id: "sep-protected-software-v1".into(),
        key_id: id.into(),
        usage: KeyUsage::WebAuthnSigning,
        algorithm: KeyAlgorithm::P256,
    }
}

pub(crate) fn same_identity(a: &PasskeyCredential, b: &PasskeyCredential) -> bool {
    a.id == b.id
        && a.rp_id == b.rp_id
        && a.credential_id == b.credential_id
        && a.user_handle == b.user_handle
        && a.provenance == b.provenance
}
fn validate_summary(journal: &Journal, summary: &ProtectedSummary) -> Result<()> {
    if summary.diagnostic
        || !same_identity(&journal.source, &summary.credential)
        || summary.public_sec1 != journal.public_sec1
        || summary.credential.signing_key != expected_reference(&journal.source.id)
        || summary.revision == 0
    {
        return Err(Error::Security(
            "broker credential does not match the migration source".into(),
        ));
    }
    Ok(())
}

fn migrate_with(
    paths: &AppPaths,
    backend: &dyn SecurityBackend,
    store: &StateStore<'_>,
    id: &str,
    socket: &Path,
    mut call: impl FnMut(Operation) -> Result<serde_json::Value>,
) -> Result<MigrationOutcome> {
    if !socket.is_absolute() {
        return Err(Error::Config("broker socket must be absolute".into()));
    }
    let mut config = Config::load(paths)?;
    if config
        .credential_broker
        .as_ref()
        .is_some_and(|configured| configured != socket)
    {
        return Err(Error::Refused(
            "a different credential broker is already configured".into(),
        ));
    }
    let mut vault = store
        .load_vault()?
        .ok_or_else(|| Error::Config("vault is empty".into()))?;
    let selected = vault
        .passkeys
        .iter()
        .position(|c| c.id == id)
        .ok_or_else(|| Error::Refused("selected passkey is not in the local vault".into()))?;
    let path = migration_path(paths, id)?;
    let owner = keychain_sep_driver::peer::effective_uid();
    let mut journal = if path.try_exists().map_err(|e| Error::io(&path, e))? {
        let data = read_bounded(&path)?;
        if data.len() > 32 * 1024 {
            return Err(Error::InvalidData("migration journal exceeds limit".into()));
        }
        let plain = backend.open(Purpose::ProtectionMigration, &data)?;
        let journal: Journal = serde_json::from_slice(&plain)?;
        if journal.version != 1
            || journal.owner != owner
            || journal.socket != socket
            || journal.source.id != id
            || journal.source.provenance != PasskeyProvenance::Synced
            || journal.source.signing_key.backend_id != backend.backend_id()
            || journal
                .destination
                .as_ref()
                .is_some_and(|key| key != &expected_reference(id))
        {
            return Err(Error::Security(
                "migration journal identity/policy mismatch".into(),
            ));
        }
        journal
    } else {
        let source = vault.passkeys[selected].clone();
        if source.provenance != PasskeyProvenance::Synced
            || source.signing_key.backend_id != backend.backend_id()
        {
            return Err(Error::Refused(
                "only an existing synced software passkey can start migration".into(),
            ));
        }
        let public = backend.public_x963(&source.signing_key)?;
        if public.len() != 65
            || public[0] != 4
            || p256::PublicKey::from_sec1_bytes(&public).is_err()
        {
            return Err(Error::Security(
                "migration source has an invalid P-256 public point".into(),
            ));
        }
        let journal = Journal {
            version: 1,
            owner,
            socket: socket.to_owned(),
            source,
            public_sec1: STANDARD.encode(public),
            destination: None,
            revision: None,
            phase: Phase::Prepared,
        };
        // Durable source reference before any server-side staging or local change.
        save_journal(&path, backend, &journal)?;
        journal
    };
    if !same_identity(&journal.source, &vault.passkeys[selected])
        || (vault.passkeys[selected].signing_key != journal.source.signing_key
            && Some(&vault.passkeys[selected].signing_key) != journal.destination.as_ref())
    {
        return Err(Error::Security(
            "local credential changed during migration".into(),
        ));
    }
    let state: ProtectionState =
        serde_json::from_value(call(Operation::ProtectionState { record: id.into() })?)?;
    for summary in [&state.active, &state.staged].into_iter().flatten() {
        validate_summary(&journal, summary)?;
    }
    if state.active.is_none() && state.staged.is_none() {
        if journal.phase != Phase::Prepared {
            return Err(Error::Refused(
                "previously verified broker credential is missing; refusing replacement".into(),
            ));
        }
        let recipient: Recipient = serde_json::from_value(call(Operation::ItemRecipient)?)?;
        let import = backend.prepare_passkey_protection(&journal.source, &recipient, owner, 0)?;
        if import.public_sec1 != journal.public_sec1 {
            return Err(Error::Security("migration source key changed".into()));
        }
        // An ambiguous transport result is returned as an error, never retried.
        // A later explicit invocation discovers any durable staging via State.
        call(Operation::ImportProtected {
            import: Box::new(import),
        })?;
    }
    let verified = call(Operation::VerifyProtected { record: id.into() })?;
    if verified
        .get("verified")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Err(Error::Security(
            "broker did not verify the migration".into(),
        ));
    }
    let state: ProtectionState =
        serde_json::from_value(call(Operation::ProtectionState { record: id.into() })?)?;
    let active = state
        .active
        .ok_or_else(|| Error::Security("verified broker credential is missing".into()))?;
    validate_summary(&journal, &active)?;
    if !active.verified
        || state.staged.is_some()
        || verified.get("revision").and_then(serde_json::Value::as_u64) != Some(active.revision)
    {
        return Err(Error::Security(
            "broker commit does not match verification".into(),
        ));
    }
    journal.phase = Phase::BrokerVerified;
    journal.destination = Some(active.credential.signing_key.clone());
    journal.revision = Some(active.revision);
    save_journal(&path, backend, &journal)?;
    vault.passkeys[selected].signing_key = active.credential.signing_key.clone();
    store.save_vault(&vault)?;
    // A crash before this config write leaves a protected reference that the
    // software signer refuses. Resume completes config; it never signs the backup.
    config.credential_broker = Some(socket.to_owned());
    config.save(paths)?;
    journal.phase = Phase::Committed;
    save_journal(&path, backend, &journal)?;
    Ok(MigrationOutcome {
        record: id.into(),
        revision: active.revision,
        source_retained: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::VaultState;
    use crate::security::SoftwareFileBackend;
    use crate::security::sep::ProviderError;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    struct Fixture {
        _directory: tempfile::TempDir,
        paths: AppPaths,
        backend: SoftwareFileBackend,
        credential: PasskeyCredential,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
            let paths =
                AppPaths::for_test(directory.path()).unwrap_or_else(|e| panic!("paths: {e}"));
            let backend = SoftwareFileBackend::new(paths.clone());
            let key = p256::SecretKey::from_slice(&[9; 32]).unwrap_or_else(|e| panic!("key: {e}"));
            let mut x963 = zeroize::Zeroizing::new(
                key.public_key().to_encoded_point(false).as_bytes().to_vec(),
            );
            x963.extend_from_slice(&key.to_bytes());
            let reference = backend
                .import_p256_x963(KeyUsage::WebAuthnSigning, &x963)
                .unwrap_or_else(|e| panic!("import: {e}"));
            let credential = PasskeyCredential {
                id: uuid::Uuid::new_v4().to_string().to_ascii_uppercase(),
                rp_id: "example.com".into(),
                provenance: PasskeyProvenance::Synced,
                credential_id: URL_SAFE_NO_PAD.encode([1; 16]),
                user_handle: URL_SAFE_NO_PAD.encode([2; 16]),
                username: "Synthetic migration".into(),
                display_name: "Synthetic migration".into(),
                created_at: 1.0,
                modified_at: 2.0,
                signing_key: reference,
            };
            StateStore::new(&paths, &backend)
                .save_vault(&VaultState {
                    schema_version: 1,
                    synced_at: 0,
                    credentials: vec![],
                    passkeys: vec![credential.clone()],
                })
                .unwrap_or_else(|e| panic!("vault: {e}"));
            Self {
                _directory: directory,
                paths,
                backend,
                credential,
            }
        }
        fn run(&self, remote: &mut Remote) -> Result<MigrationOutcome> {
            migrate_with(
                &self.paths,
                &self.backend,
                &StateStore::new(&self.paths, &self.backend),
                &self.credential.id,
                Path::new("/run/keychain/synthetic.sock"),
                |op| remote.call(op),
            )
        }
        fn reference(&self) -> KeyRef {
            StateStore::new(&self.paths, &self.backend)
                .load_vault()
                .unwrap_or_else(|e| panic!("load: {e}"))
                .unwrap_or_else(|| panic!("missing vault"))
                .passkeys[0]
                .signing_key
                .clone()
        }
    }
    struct Remote {
        state: ProtectionState,
        recipient: Recipient,
        imports: usize,
        verifies: usize,
        fail_stage: bool,
        fail_commit: bool,
        config_failure: Option<PathBuf>,
    }
    impl Remote {
        fn new() -> Self {
            let key =
                p256::SecretKey::from_slice(&[7; 32]).unwrap_or_else(|e| panic!("recipient: {e}"));
            Self {
                state: ProtectionState {
                    active: None,
                    staged: None,
                },
                recipient: Recipient {
                    id: uuid::Uuid::new_v4().to_string(),
                    public_sec1: STANDARD
                        .encode(key.public_key().to_encoded_point(false).as_bytes()),
                },
                imports: 0,
                verifies: 0,
                fail_stage: false,
                fail_commit: false,
                config_failure: None,
            }
        }
        fn call(&mut self, op: Operation) -> Result<serde_json::Value> {
            match op {
                Operation::ProtectionState { .. } => Ok(serde_json::to_value(&self.state)?),
                Operation::ItemRecipient => Ok(serde_json::to_value(&self.recipient)?),
                Operation::ImportProtected { import } => {
                    self.imports += 1;
                    assert!(!import.diagnostic);
                    assert!(import.sealed.len() > 81);
                    let mut credential = import.credential.clone();
                    credential.signing_key = expected_reference(&credential.id);
                    self.state.staged = Some(ProtectedSummary {
                        credential,
                        public_sec1: import.public_sec1,
                        revision: 1,
                        recipient_id: import.recipient_id,
                        verified: false,
                        diagnostic: false,
                    });
                    if std::mem::take(&mut self.fail_stage) {
                        return Err(Error::Sep(ProviderError::AmbiguousCompletion));
                    }
                    Ok(serde_json::json!({"revision":1,"verified":false}))
                }
                Operation::VerifyProtected { .. } => {
                    self.verifies += 1;
                    if let Some(mut staged) = self.state.staged.take() {
                        staged.verified = true;
                        self.state.active = Some(staged);
                    }
                    if std::mem::take(&mut self.fail_commit) {
                        return Err(Error::Sep(ProviderError::AmbiguousCompletion));
                    }
                    if let Some(path) = self.config_failure.take() {
                        std::fs::create_dir(&path)
                            .unwrap_or_else(|e| panic!("failure injection: {e}"));
                    }
                    Ok(serde_json::json!({"revision":1,"verified":true}))
                }
                _ => panic!("unexpected migration operation"),
            }
        }
    }

    #[test]
    fn resume_after_ambiguous_staging_keeps_identity_and_retains_source_without_fallback() {
        let fixture = Fixture::new();
        let mut remote = Remote::new();
        remote.fail_stage = true;
        assert!(fixture.run(&mut remote).is_err());
        assert_eq!(fixture.reference(), fixture.credential.signing_key);
        assert_eq!(remote.imports, 1);
        assert_eq!(remote.verifies, 0);
        let outcome = fixture
            .run(&mut remote)
            .unwrap_or_else(|e| panic!("resume: {e}"));
        assert!(outcome.source_retained);
        assert_eq!(
            fixture.reference(),
            expected_reference(&fixture.credential.id)
        );
        assert_eq!(remote.imports, 1);
        assert_eq!(remote.verifies, 1);
        assert!(
            fixture
                .backend
                .public_x963(&fixture.credential.signing_key)
                .is_ok()
        );
        assert!(
            fixture
                .backend
                .sign_p256_sha256(&fixture.reference(), b"no fallback")
                .is_err()
        );
        assert_eq!(
            Config::load(&fixture.paths)
                .unwrap_or_else(|e| panic!("config: {e}"))
                .credential_broker,
            Some(PathBuf::from("/run/keychain/synthetic.sock"))
        );
        remote.state.active = None;
        assert!(fixture.run(&mut remote).is_err());
        assert_eq!(remote.imports, 1); // missing verified destination never regenerates it
    }
    #[test]
    fn resume_after_ambiguous_broker_commit_does_not_reimport_or_lose_source() {
        let fixture = Fixture::new();
        let mut remote = Remote::new();
        remote.fail_commit = true;
        assert!(fixture.run(&mut remote).is_err());
        assert_eq!(fixture.reference(), fixture.credential.signing_key);
        fixture
            .run(&mut remote)
            .unwrap_or_else(|e| panic!("resume committed broker: {e}"));
        assert_eq!(remote.imports, 1);
        assert_eq!(remote.verifies, 2);
    }
    #[test]
    fn config_write_interruption_leaves_a_refused_software_reference_then_resumes() {
        let fixture = Fixture::new();
        let mut remote = Remote::new();
        remote.config_failure = Some(fixture.paths.config_file());
        assert!(fixture.run(&mut remote).is_err());
        assert_eq!(
            fixture.reference(),
            expected_reference(&fixture.credential.id)
        );
        assert!(
            fixture
                .backend
                .sign_p256_sha256(&fixture.reference(), b"refused")
                .is_err()
        );
        std::fs::remove_dir(fixture.paths.config_file())
            .unwrap_or_else(|e| panic!("clear injected config obstacle: {e}"));
        fixture
            .run(&mut remote)
            .unwrap_or_else(|e| panic!("resume config: {e}"));
        assert_eq!(remote.imports, 1);
    }
    #[test]
    fn mismatched_broker_identity_is_refused_before_biometric_verification() {
        let fixture = Fixture::new();
        let mut remote = Remote::new();
        remote.fail_stage = true;
        assert!(fixture.run(&mut remote).is_err());
        remote
            .state
            .staged
            .as_mut()
            .unwrap_or_else(|| panic!("staged"))
            .credential
            .rp_id = "attacker.example".into();
        assert!(fixture.run(&mut remote).is_err());
        assert_eq!(remote.verifies, 0);
        assert_eq!(fixture.reference(), fixture.credential.signing_key);
    }
}
