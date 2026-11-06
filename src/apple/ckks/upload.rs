//! Durable, storage-neutral upload coordination. A production transport must
//! implement atomic unchanged-pointer/create-only semantics; no Apple write
//! implementation or browser authorization grant is provided by this module.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::write::{CurrentKey, KeyClass};
use super::{Record, ZoneIdentity};
use crate::apple::pipeline::{RecoveredTlk, decrypt_items, unwrap_class_keys};
use crate::model::{PasskeyCredential, PasskeyProvenance};
use crate::paths::{atomic_write_private, create_private_exclusive, read_bounded};
use crate::security::{KeyAlgorithm, KeyUsage, Purpose, SecurityBackend};
use crate::{Error, Result};

const MAX_JOURNAL: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub owner: u32,
    pub account_fingerprint: String,
    pub peer_id: String,
    pub transaction: Uuid,
    pub request_sha256: String,
    pub zone: ZoneIdentity,
}
impl Binding {
    fn validate(&self) -> Result<()> {
        let tphash = |value: &str| {
            value
                .strip_prefix("SHA256:")
                .filter(|value| value.len() == 44)
                .and_then(|value| STANDARD.decode(value).ok())
                .is_some_and(|value| value.len() == 32)
        };
        if self.owner == 0
            || self.transaction.get_version_num() != 4
            || !tphash(&self.account_fingerprint)
            || !tphash(&self.peer_id)
            || self.request_sha256.len() != 64
            || hex::decode(&self.request_sha256).is_err()
            || self.zone.name != "Passwords"
            || self.zone.owner.is_empty()
            || self.zone.owner.len() > 512
        {
            return Err(invalid("invalid account/peer/request/zone binding"));
        }
        Ok(())
    }
}

/// Construct only from an authenticated, complete single-zone fetch. Possession
/// of TLS-authenticated records does not authenticate TLKs: callers must obtain
/// the roots from verified Octagon shares, as the regular sync pipeline does.
pub struct Snapshot {
    zone: ZoneIdentity,
    records: Vec<Record>,
    tlks: Vec<RecoveredTlk>,
}
impl Snapshot {
    /// Fetch every page before absence can authorize a retry or a new save.
    pub fn fetch(
        transport: &crate::apple::cloudkit::CloudKitTransport<'_>,
        zone: ZoneIdentity,
        tlks: Vec<RecoveredTlk>,
    ) -> Result<Self> {
        if zone.owner != transport.user_id() {
            return Err(invalid(
                "fetch owner differs from the authenticated account",
            ));
        }
        Self::fetch_with(zone, tlks, |request| transport.fetch_records(request))
    }
    fn fetch_with(
        zone: ZoneIdentity,
        tlks: Vec<RecoveredTlk>,
        mut read: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        let zone_id = super::record_zone_identifier(&zone.name, &zone.owner);
        let mut records = Vec::new();
        let mut token: Option<Vec<u8>> = None;
        let mut seen = BTreeSet::new();
        let mut bytes = 0usize;
        for _ in 0..1000 {
            let request = super::build_retrieve_changes_request(&zone_id, token.as_deref(), 500);
            let page = super::parse_retrieve_changes_response(&read(&request)?)?;
            for record in &page.records {
                bytes = bytes
                    .checked_add(record.server_precondition(&zone)?.encoded_record.len())
                    .ok_or_else(|| invalid("snapshot size overflow"))?;
            }
            if bytes > 64 * 1024 * 1024 || records.len() + page.records.len() > 65536 {
                return Err(invalid("snapshot exceeds bounds"));
            }
            records.extend(page.records);
            if page.status == 3 {
                return Self::new(zone, records, tlks);
            }
            let next = page
                .continuation
                .ok_or_else(|| invalid("missing page cursor"))?;
            if next.len() > 16 * 1024 || !seen.insert(next.clone()) {
                return Err(invalid("oversized or repeated page cursor"));
            }
            token = Some(next);
        }
        Err(invalid("snapshot exceeded the 1000-page bound"))
    }
    fn new(zone: ZoneIdentity, records: Vec<Record>, tlks: Vec<RecoveredTlk>) -> Result<Self> {
        if records.len() > 65536 || tlks.len() > 4096 {
            return Err(invalid("snapshot exceeds bounds"));
        }
        let mut seen = BTreeSet::new();
        let mut encoded_bytes = 0usize;
        for record in &records {
            if !seen.insert(&record.name) {
                return Err(invalid("duplicate snapshot record"));
            }
            let server = record.server_precondition(&zone)?;
            encoded_bytes = encoded_bytes
                .checked_add(server.encoded_record.len())
                .ok_or_else(|| invalid("snapshot size overflow"))?;
            if encoded_bytes > 64 * 1024 * 1024 {
                return Err(invalid("snapshot encoding exceeds bounds"));
            }
        }
        let mut roots = BTreeMap::new();
        for root in tlks.iter().filter(|root| root.zone_name == zone.name) {
            if root.keyclass != "tlk" || root.key.len() != 64 {
                return Err(invalid("invalid authenticated root"));
            }
            Uuid::parse_str(&root.uuid).map_err(|_| invalid("invalid authenticated TLK UUID"))?;
            if let Some(previous) = roots.insert(&root.uuid, &root.key) {
                if previous != &root.key {
                    return Err(invalid("conflicting authenticated roots"));
                }
            }
        }
        if roots.is_empty() {
            return Err(invalid("snapshot has no authenticated zone root"));
        }
        Ok(Self {
            zone,
            records,
            tlks,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanData {
    binding: Binding,
    credential: PasskeyCredential,
    public_sec1: String,
    record: Record,
    current_pointer: Record,
}

/// No Deserialize implementation: an untrusted IPC client cannot manufacture a
/// verified plan. The encrypted journal loads its private representation only.
#[derive(Clone)]
pub struct PreparedUpload(PlanData);
impl PreparedUpload {
    pub fn from_snapshot(
        binding: Binding,
        credential: PasskeyCredential,
        public_sec1: &[u8],
        record: Record,
        snapshot: &Snapshot,
    ) -> Result<Self> {
        binding.validate()?;
        let current = CurrentKey::from_snapshot(
            &binding.zone.name,
            &snapshot.records,
            &snapshot.tlks,
            KeyClass::WhenUnlocked,
        )?;
        if snapshot.zone != binding.zone
            || snapshot.records.iter().any(|r| r.name == record.name)
            || record.string("parentkeyref") != Some(current.key_id())
        {
            return Err(invalid(
                "prepared item does not match an unused slot/current key",
            ));
        }
        let plan = PlanData {
            binding,
            credential,
            public_sec1: STANDARD.encode(public_sec1),
            record,
            current_pointer: current.current_pointer().clone(),
        };
        plan.validate()?;
        plan.verify_payload(&plan.record, snapshot)?;
        Ok(Self(plan))
    }
    pub fn binding(&self) -> &Binding {
        &self.0.binding
    }
}
impl PlanData {
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        let credential = &self.credential;
        let key = &credential.signing_key;
        if credential.id != self.binding.transaction.to_string()
            || credential.provenance != PasskeyProvenance::Synced
            || key.backend_id != "sep-protected-software-v1"
            || key.key_id != credential.id
            || key.usage != KeyUsage::WebAuthnSigning
            || key.algorithm != KeyAlgorithm::P256
            || self.record.server.is_some()
            || self.record.name != credential.id
            || self.record.record_type != "item"
            || self.record.integer("gen") != Some(0)
            || self.record.integer("encver") != Some(2)
            || self.current_pointer.name != "classA"
            || self.current_pointer.record_type != "currentkey"
            || self.record.string("parentkeyref") != self.current_pointer.string("parentkeyref")
            || self.record.fields.len() != 5
        {
            return Err(invalid(
                "prepared identity, key policy or ciphertext fields do not match",
            ));
        }
        self.current_pointer
            .server_precondition(&self.binding.zone)?;
        let public = STANDARD
            .decode(&self.public_sec1)
            .map_err(|_| invalid("invalid public encoding"))?;
        if public.len() != 65
            || public[0] != 4
            || p256::PublicKey::from_sec1_bytes(&public).is_err()
        {
            return Err(invalid("invalid expected P-256 public point"));
        }
        let data = self
            .record
            .bytes("data")
            .ok_or_else(|| invalid("missing item ciphertext"))?;
        let wrapped = self
            .record
            .string("wrappedkey")
            .and_then(|s| STANDARD.decode(s).ok())
            .ok_or_else(|| invalid("invalid wrapped item key"))?;
        if data.len() < 32 || data.len() > 1024 * 1024 + 128 || wrapped.len() != 80 {
            return Err(invalid("invalid ciphertext/wrapped-key length"));
        }
        Ok(())
    }
    fn verify_payload(&self, record: &Record, snapshot: &Snapshot) -> Result<()> {
        if snapshot.zone != self.binding.zone
            || record.name != self.record.name
            || record.record_type != "item"
            || self
                .record
                .fields
                .iter()
                .any(|(key, value)| record.fields.get(key) != Some(value))
        {
            return Err(Error::Security(
                "fetched record differs from the prepared upload".into(),
            ));
        }
        let roots = snapshot
            .tlks
            .iter()
            .filter(|root| root.zone_name == self.binding.zone.name)
            .map(|root| (root.uuid.clone(), root.key.clone()))
            .collect();
        let sync_keys: Vec<_> = snapshot
            .records
            .iter()
            .filter(|r| r.record_type == "synckey")
            .cloned()
            .collect();
        let keys = unwrap_class_keys(&sync_keys, &roots)?;
        let items = decrypt_items(std::slice::from_ref(record), &keys);
        let item = items.first().ok_or_else(|| {
            Error::Security("fetched upload did not decrypt with authenticated keys".into())
        })?;
        let recovered = crate::passkey::from_item(&record.name, &item.fields)?
            .ok_or_else(|| invalid("fetched upload is not a passkey"))?;
        let expected = &self.credential;
        if recovered.rp_id != expected.rp_id
            || URL_SAFE_NO_PAD.encode(&recovered.credential_id) != expected.credential_id
            || URL_SAFE_NO_PAD.encode(&recovered.user_handle) != expected.user_handle
            || recovered.username != expected.username
            || recovered.display_name != expected.display_name
            || STANDARD.encode(recovered.public_x963()) != self.public_sec1
        {
            return Err(Error::Security(
                "fetched upload changed the credential identity".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Phase {
    Prepared,
    Attempted { attempt: Uuid },
    Accepted { attempt: Uuid, change_tag: String },
    FetchVerified { change_tag: String },
    Rejected,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    plan: PlanData,
    phase: Phase,
    attempts: Vec<Uuid>,
}

/// The accepted record must include its server encoding, tag and zone. A
/// precondition failure guarantees the ENTIRE atomic operation was rejected.
pub enum SaveOutcome {
    Accepted(Record),
    PreconditionFailed,
}
pub trait UploadIo {
    fn fetch_zone(&mut self, zone: &ZoneIdentity) -> Result<Snapshot>;
    fn create_atomic(
        &mut self,
        attempt: Uuid,
        zone: &ZoneIdentity,
        record: &Record,
        unchanged_pointer: &Record,
    ) -> Result<SaveOutcome>;
}

/// The containing private directory and encryption backend are supplied by the
/// broker registry. The same implementation uses temporary user-owned fixtures
/// in offline tests; it never creates a root, keypair, account or trust identity.
pub struct UploadStore<'a> {
    directory: PathBuf,
    backend: &'a dyn SecurityBackend,
}
pub struct Session<'a> {
    store: UploadStore<'a>,
    path: PathBuf,
    journal: Journal,
    _lock: File,
    healthy: bool,
}
impl<'a> UploadStore<'a> {
    pub fn new(directory: &Path, backend: &'a dyn SecurityBackend) -> Result<Self> {
        let meta = std::fs::symlink_metadata(directory).map_err(|e| Error::io(directory, e))?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != keychain_sep_driver::peer::effective_uid()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(invalid("upload store must be a private owned directory"));
        }
        Ok(Self {
            directory: directory.into(),
            backend,
        })
    }
    fn lock(&self, transaction: Uuid) -> Result<File> {
        let path = self.directory.join(format!(".upload-{transaction}.lock"));
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        let meta = file.metadata().map_err(|e| Error::io(&path, e))?;
        if !meta.is_file()
            || meta.uid() != keychain_sep_driver::peer::effective_uid()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(invalid("unsafe upload lock file"));
        }
        fs2::FileExt::try_lock_exclusive(&file)
            .map_err(|_| Error::Refused("this upload transaction is already active".into()))?;
        Ok(file)
    }
    pub fn prepare(self, upload: PreparedUpload) -> Result<Session<'a>> {
        upload.0.validate()?;
        let binding = upload.0.binding.clone();
        let lock = self.lock(binding.transaction)?;
        let path = self
            .directory
            .join(format!("upload-{}.enc", binding.transaction));
        if path.try_exists().map_err(|e| Error::io(&path, e))? {
            let session = self.load(path, lock, &binding)?;
            if serde_json::to_vec(&session.journal.plan)? != serde_json::to_vec(&upload.0)? {
                return Err(Error::Security(
                    "existing upload transaction has different prepared data".into(),
                ));
            }
            return Ok(session);
        }
        let session = Session {
            store: self,
            path,
            journal: Journal {
                version: 1,
                plan: upload.0,
                phase: Phase::Prepared,
                attempts: vec![],
            },
            _lock: lock,
            healthy: true,
        };
        let envelope = session.envelope()?;
        create_private_exclusive(&session.path, &envelope)?;
        Ok(session)
    }
    pub fn resume(self, binding: &Binding) -> Result<Session<'a>> {
        binding.validate()?;
        let lock = self.lock(binding.transaction)?;
        let path = self
            .directory
            .join(format!("upload-{}.enc", binding.transaction));
        self.load(path, lock, binding)
    }
    fn load(self, path: PathBuf, lock: File, binding: &Binding) -> Result<Session<'a>> {
        let data = read_bounded(&path)?;
        if data.len() > MAX_JOURNAL + 128 {
            return Err(invalid("journal exceeds bound"));
        }
        let plain = self.backend.open(Purpose::SyncUpload, &data)?;
        if plain.len() > MAX_JOURNAL {
            return Err(invalid("journal plaintext exceeds bound"));
        }
        let journal: Journal = serde_json::from_slice(&plain)?;
        if journal.version != 1
            || journal.plan.binding != *binding
            || journal.attempts.len() > 16
            || journal.attempts.iter().any(|id| id.get_version_num() != 4)
            || journal.attempts.iter().collect::<BTreeSet<_>>().len() != journal.attempts.len()
        {
            return Err(invalid("journal binding/version/attempt history mismatch"));
        }
        match &journal.phase {
            Phase::Attempted { attempt } | Phase::Accepted { attempt, .. }
                if journal.attempts.last() != Some(attempt) =>
            {
                return Err(invalid("invalid current upload attempt"));
            }
            Phase::Accepted { change_tag, .. } | Phase::FetchVerified { change_tag }
                if change_tag.is_empty() || change_tag.len() > 4096 =>
            {
                return Err(invalid("invalid saved server tag"));
            }
            _ => (),
        }
        journal.plan.validate()?;
        Ok(Session {
            store: self,
            path,
            journal,
            _lock: lock,
            healthy: true,
        })
    }
}
impl Session<'_> {
    pub fn phase(&self) -> Result<&Phase> {
        self.check_healthy()?;
        Ok(&self.journal.phase)
    }
    pub fn credential(&self) -> &PasskeyCredential {
        &self.journal.plan.credential
    }
    fn envelope(&self) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(serde_json::to_vec(&self.journal)?);
        if plain.len() > MAX_JOURNAL {
            return Err(invalid("journal exceeds bound"));
        }
        self.store.backend.seal(Purpose::SyncUpload, &plain)
    }
    fn checkpoint(&mut self, phase: Phase) -> Result<()> {
        self.check_healthy()?;
        // A failed rename/fsync can leave either old or new bytes on disk. Never
        // trust in-memory phase after ANY persistence error; reopen/reconcile.
        self.healthy = false;
        self.journal.phase = phase;
        atomic_write_private(&self.path, &self.envelope()?)?;
        self.healthy = true;
        Ok(())
    }
    fn check_healthy(&self) -> Result<()> {
        if !self.healthy {
            return Err(Error::Refused(
                "upload checkpoint failed; reopen and reconcile this transaction".into(),
            ));
        }
        Ok(())
    }
    fn check_pointer(&self, snapshot: &Snapshot) -> Result<()> {
        if snapshot.zone != self.journal.plan.binding.zone {
            return Err(invalid("snapshot zone changed"));
        }
        let saved = &self.journal.plan.current_pointer;
        let current = snapshot
            .records
            .iter()
            .find(|record| record.name == saved.name)
            .ok_or_else(|| invalid("current pointer disappeared"))?;
        let metadata = current.server_precondition(&snapshot.zone)?;
        if current.record_type != saved.record_type
            || current.fields != saved.fields
            || metadata.change_tag != saved.server_precondition(&snapshot.zone)?.change_tag
        {
            return Err(Error::Refused(
                "current key/precondition changed; keep this key and prepare a reconciled upload"
                    .into(),
            ));
        }
        Ok(())
    }
    pub fn advance(&mut self, io: &mut dyn UploadIo) -> Result<()> {
        self.check_healthy()?;
        if matches!(self.journal.phase, Phase::FetchVerified { .. }) {
            return Ok(());
        }
        let zone = self.journal.plan.binding.zone.clone();
        let snapshot = io.fetch_zone(&zone)?;
        if let Some(record) = snapshot
            .records
            .iter()
            .find(|r| r.name == self.journal.plan.record.name)
        {
            self.journal.plan.verify_payload(record, &snapshot)?;
            let tag = record
                .server_precondition(&zone)?
                .change_tag
                .clone()
                .ok_or_else(|| invalid("fetched record omitted tag"))?;
            // No caller-supplied "uploaded" boolean: exact ciphertext, decrypted
            // identity and expected public point have all been checked here.
            return self.checkpoint(Phase::FetchVerified { change_tag: tag });
        }
        if !matches!(self.journal.phase, Phase::Prepared) {
            return Err(Error::Refused(
                "upload outcome is unresolved; no automatic resend or new key".into(),
            ));
        }
        if let Err(error) = self.check_pointer(&snapshot) {
            self.checkpoint(Phase::Rejected)?;
            return Err(error);
        }
        if self.journal.attempts.len() >= 16 {
            return Err(Error::Refused("upload retry budget exhausted".into()));
        }
        let attempt = Uuid::new_v4();
        self.journal.attempts.push(attempt);
        self.checkpoint(Phase::Attempted { attempt })?; // Must precede ANY send.
        match io.create_atomic(
            attempt,
            &zone,
            &self.journal.plan.record,
            &self.journal.plan.current_pointer,
        )? {
            SaveOutcome::PreconditionFailed => {
                self.checkpoint(Phase::Rejected)?;
                return Err(Error::Refused(
                    "Apple rejected the atomic precondition; prepared key retained".into(),
                ));
            }
            SaveOutcome::Accepted(record) => {
                if record.name != self.journal.plan.record.name
                    || record.record_type != "item"
                    || self
                        .journal
                        .plan
                        .record
                        .fields
                        .iter()
                        .any(|(key, value)| record.fields.get(key) != Some(value))
                {
                    return Err(Error::Security(
                        "save acknowledgment did not identify the prepared record".into(),
                    ));
                }
                let tag = record
                    .server_precondition(&zone)?
                    .change_tag
                    .clone()
                    .ok_or_else(|| invalid("save acknowledgment omitted tag"))?;
                self.checkpoint(Phase::Accepted {
                    attempt,
                    change_tag: tag,
                })?;
            }
        }
        self.advance(io) // Independent post-acceptance fetch/decrypt, no resend.
    }
    /// Explicit retry only after a fresh complete snapshot reports absence and
    /// the original current-key precondition still holds. Ciphertext/identity
    /// remain unchanged. Known acceptance/rejection never takes this path.
    pub fn retry_after_absence(&mut self, io: &mut dyn UploadIo) -> Result<()> {
        self.check_healthy()?;
        if !matches!(self.journal.phase, Phase::Attempted { .. }) {
            return Err(Error::Refused(
                "only an uncertain attempt can be retried".into(),
            ));
        }
        let snapshot = io.fetch_zone(&self.journal.plan.binding.zone)?;
        if snapshot
            .records
            .iter()
            .any(|r| r.name == self.journal.plan.record.name)
        {
            return Err(Error::Refused(
                "the record exists; reconcile it instead of resending".into(),
            ));
        }
        self.check_pointer(&snapshot)?;
        self.checkpoint(Phase::Prepared)
    }
}
fn invalid(message: &str) -> Error {
    Error::InvalidData(format!("CKKS upload: {message}"))
}

#[cfg(test)]
mod tests {
    use super::super::{FieldValue, test_support::server_record};
    use super::*;
    use crate::security::{FileRootKeySource, KeyRef, RootKeySource, SoftwareFileBackend};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn prepare_checks_encrypted_identity_before_creating_a_journal() -> Result<()> {
        let mut f = Fixture::new()?;
        let snapshot = f.io.fetch_zone(&f.plan.0.binding.zone)?;
        let other = p256::SecretKey::from_slice(&[8u8; 32]).map_err(|_| invalid("test key"))?;
        let public = other.public_key().to_encoded_point(false);
        assert!(
            PreparedUpload::from_snapshot(
                f.plan.0.binding.clone(),
                f.plan.0.credential.clone(),
                public.as_bytes(),
                f.plan.0.record.clone(),
                &snapshot
            )
            .is_err()
        );
        let expected = STANDARD
            .decode(&f.plan.0.public_sec1)
            .map_err(|_| invalid("test point"))?;
        let mut metadata = f.plan.0.credential.clone();
        metadata.username = "different-user".into();
        assert!(
            PreparedUpload::from_snapshot(
                f.plan.0.binding.clone(),
                metadata,
                &expected,
                f.plan.0.record.clone(),
                &snapshot
            )
            .is_err()
        );
        assert!(
            std::fs::read_dir(&f.directory)
                .map_err(|e| Error::io(&f.directory, e))?
                .next()
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn snapshot_fetch_requires_all_pages_and_rejects_partial_or_repeated_cursors() -> Result<()> {
        use crate::proto::{Writer, decode_fields, first_bytes};
        let f = Fixture::new()?;
        let change = |record: &Record| -> Result<Vec<u8>> {
            Ok(Writer::new()
                .message(
                    5,
                    &record
                        .server
                        .as_ref()
                        .ok_or_else(|| invalid("test server metadata"))?
                        .encoded_record,
                )
                .finish())
        };
        let first = Writer::new()
            .message(1, &change(&f.io.records[0])?)
            .bytes(2, b"cursor-1")
            .uint64(4, 1)
            .finish();
        let last = Writer::new()
            .message(1, &change(&f.io.records[1])?)
            .uint64(4, 3)
            .finish();
        let mut calls = 0;
        let snapshot = Snapshot::fetch_with(f.io.zone.clone(), f.io.tlks.clone(), |request| {
            calls += 1;
            if calls == 1 {
                assert!(first_bytes(&decode_fields(request)?, 1).is_none());
                Ok(first.clone())
            } else {
                assert_eq!(
                    first_bytes(&decode_fields(request)?, 1),
                    Some(b"cursor-1".as_slice())
                );
                Ok(last.clone())
            }
        })?;
        assert_eq!(calls, 2);
        assert_eq!(snapshot.records.len(), 2);
        let repeat = Writer::new().bytes(2, b"cursor-1").uint64(4, 1).finish();
        assert!(
            Snapshot::fetch_with(f.io.zone.clone(), f.io.tlks.clone(), |_| Ok(repeat.clone()))
                .is_err()
        );
        assert!(
            Snapshot::fetch_with(f.io.zone.clone(), f.io.tlks.clone(), |_| Ok(Writer::new()
                .uint64(4, 1)
                .finish()))
            .is_err()
        );
        Ok(())
    }

    struct FailableRoot {
        inner: FileRootKeySource,
        denied: Arc<AtomicBool>,
    }
    impl RootKeySource for FailableRoot {
        fn root_key(&self) -> Result<Zeroizing<[u8; 32]>> {
            if self.denied.load(Ordering::Acquire) {
                return Err(Error::Refused("synthetic persistence failure".into()));
            }
            self.inner.root_key()
        }
    }
    struct Fixture {
        _root: tempfile::TempDir,
        directory: PathBuf,
        backend: SoftwareFileBackend,
        denied: Arc<AtomicBool>,
        plan: PreparedUpload,
        io: FakeIo,
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let root = tempfile::tempdir().map_err(|e| Error::io("temporary root", e))?;
            let paths = crate::paths::AppPaths::for_test(&root.path().join("crypto"))?;
            let denied = Arc::new(AtomicBool::new(false));
            let source = FailableRoot {
                inner: FileRootKeySource::new(paths.clone()),
                denied: denied.clone(),
            };
            let backend = SoftwareFileBackend::with_root_source(paths, Box::new(source));
            let directory = root.path().join("uploads");
            std::fs::create_dir(&directory).map_err(|e| Error::io(&directory, e))?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::io(&directory, e))?;
            let zone = ZoneIdentity {
                name: "Passwords".into(),
                owner: "test-ck-owner".into(),
            };
            let binding = Binding {
                owner: 1001,
                account_fingerprint: format!("SHA256:{}", STANDARD.encode([1u8; 32])),
                peer_id: format!("SHA256:{}", STANDARD.encode([2u8; 32])),
                transaction: Uuid::new_v4(),
                request_sha256: "a1".repeat(32),
                zone: zone.clone(),
            };
            let id = binding.transaction.to_string();
            let credential = PasskeyCredential {
                provenance: PasskeyProvenance::Synced,
                id: id.clone(),
                rp_id: "example.com".into(),
                credential_id: URL_SAFE_NO_PAD.encode([3u8; 20]),
                user_handle: URL_SAFE_NO_PAD.encode(b"user"),
                username: "User".into(),
                display_name: "Test User".into(),
                created_at: 1700000000.0,
                modified_at: 1700000000.0,
                signing_key: KeyRef {
                    backend_id: "sep-protected-software-v1".into(),
                    key_id: id,
                    usage: KeyUsage::WebAuthnSigning,
                    algorithm: KeyAlgorithm::P256,
                },
            };
            let secret =
                p256::SecretKey::from_slice(&[7u8; 32]).map_err(|_| invalid("test scalar"))?;
            let public = secret.public_key().to_encoded_point(false);
            let mut private = Zeroizing::new(public.as_bytes().to_vec());
            private.extend_from_slice(&secret.to_bytes());
            let tlk_id = Uuid::new_v4().to_string();
            let class_id = Uuid::new_v4().to_string();
            let root_key = [4u8; 64];
            let class_key = [5u8; 64];
            let pointer = Record {
                server: None,
                name: "classA".into(),
                record_type: "currentkey".into(),
                fields: BTreeMap::from([(
                    "parentkeyref".into(),
                    FieldValue::Reference(class_id.clone()),
                )]),
            };
            let class = Record {
                server: None,
                name: class_id,
                record_type: "synckey".into(),
                fields: BTreeMap::from([
                    ("parentkeyref".into(), FieldValue::Reference(tlk_id.clone())),
                    ("class".into(), FieldValue::String("classA".into())),
                    (
                        "wrappedkey".into(),
                        FieldValue::String(STANDARD.encode(
                            crate::apple::crypto::aes_siv_wrap_key(&root_key, &class_key)?,
                        )),
                    ),
                ]),
            };
            let records = vec![
                server_record(&pointer, &zone, "pointer-1")?,
                server_record(&class, &zone, "key-1")?,
            ];
            let tlks = vec![RecoveredTlk {
                uuid: tlk_id,
                zone_name: zone.name.clone(),
                keyclass: "tlk".into(),
                key: Zeroizing::new(root_key.to_vec()),
            }];
            let current =
                CurrentKey::from_snapshot(&zone.name, &records, &tlks, KeyClass::WhenUnlocked)?;
            let record =
                current.seal_new_item(&crate::passkey::encode_sync_item(&credential, &private)?)?;
            let snapshot = Snapshot::new(zone.clone(), records.clone(), tlks.clone())?;
            let plan = PreparedUpload::from_snapshot(
                binding,
                credential,
                public.as_bytes(),
                record,
                &snapshot,
            )?;
            let io = FakeIo {
                zone,
                records,
                tlks,
                remote: None,
                writes: vec![],
                lost_response: false,
                commit: true,
                reject: false,
                tamper_fetch: false,
                poison_ack: None,
            };
            Ok(Self {
                _root: root,
                directory,
                backend,
                denied,
                plan,
                io,
            })
        }
    }
    struct FakeIo {
        zone: ZoneIdentity,
        records: Vec<Record>,
        tlks: Vec<RecoveredTlk>,
        remote: Option<Record>,
        writes: Vec<(Uuid, Record)>,
        lost_response: bool,
        commit: bool,
        reject: bool,
        tamper_fetch: bool,
        poison_ack: Option<Arc<AtomicBool>>,
    }
    impl UploadIo for FakeIo {
        fn fetch_zone(&mut self, zone: &ZoneIdentity) -> Result<Snapshot> {
            assert_eq!(zone, &self.zone);
            let mut records = self.records.clone();
            if let Some(remote) = &self.remote {
                let mut record = remote.clone();
                if self.tamper_fetch {
                    record.fields.insert("gen".into(), FieldValue::Integer(999));
                    record = server_record(&record, zone, "tampered")?;
                }
                records.push(record);
            }
            Snapshot::new(zone.clone(), records, self.tlks.clone())
        }
        fn create_atomic(
            &mut self,
            attempt: Uuid,
            zone: &ZoneIdentity,
            record: &Record,
            pointer: &Record,
        ) -> Result<SaveOutcome> {
            assert_eq!(zone, &self.zone);
            assert_eq!(
                pointer.server_precondition(zone)?.change_tag.as_deref(),
                Some("pointer-1")
            );
            self.writes.push((attempt, record.clone()));
            if self.reject {
                return Ok(SaveOutcome::PreconditionFailed);
            }
            if self.commit {
                self.remote = Some(server_record(record, zone, "saved-1")?);
            }
            if self.lost_response {
                return Err(Error::Apple("synthetic lost response".into()));
            }
            if let Some(denied) = &self.poison_ack {
                denied.store(true, Ordering::Release);
            }
            Ok(SaveOutcome::Accepted(
                self.remote
                    .clone()
                    .ok_or_else(|| invalid("no simulated server record"))?,
            ))
        }
    }

    #[test]
    fn accepted_upload_requires_independent_fetch_and_reopens_without_another_write() -> Result<()>
    {
        let mut f = Fixture::new()?;
        let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
        assert_eq!(session.phase()?, &Phase::Prepared);
        assert!(
            UploadStore::new(&f.directory, &f.backend)?
                .resume(f.plan.binding())
                .is_err()
        ); // Per-transaction lock.
        session.advance(&mut f.io)?;
        assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
        assert_eq!(f.io.writes.len(), 1);
        assert_eq!(session.credential(), &f.plan.0.credential);
        drop(session);
        let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
        session.advance(&mut f.io)?;
        assert_eq!(f.io.writes.len(), 1);
        let bytes = std::fs::read(&session.path).map_err(|e| Error::io(&session.path, e))?;
        assert!(!bytes.windows(b"Test User".len()).any(|s| s == b"Test User"));
        assert!(f.backend.open(Purpose::Vault, &bytes).is_err());
        Ok(())
    }

    #[test]
    fn ambiguous_commit_reconciles_exact_identity_and_never_resends_automatically() -> Result<()> {
        let mut f = Fixture::new()?;
        f.io.lost_response = true;
        let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
        assert!(session.advance(&mut f.io).is_err());
        assert!(matches!(session.phase()?, Phase::Attempted { .. }));
        drop(session);
        let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
        session.advance(&mut f.io)?; // Server already has this exact ciphertext/key.
        assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
        assert_eq!(f.io.writes.len(), 1);
        Ok(())
    }

    #[test]
    fn unresolved_absence_requires_explicit_retry_with_identical_ciphertext() -> Result<()> {
        let mut f = Fixture::new()?;
        f.io.lost_response = true;
        f.io.commit = false;
        let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
        assert!(session.advance(&mut f.io).is_err());
        assert!(session.advance(&mut f.io).is_err());
        assert_eq!(f.io.writes.len(), 1);
        session.retry_after_absence(&mut f.io)?;
        f.io.lost_response = false;
        f.io.commit = true;
        session.advance(&mut f.io)?;
        assert_eq!(f.io.writes.len(), 2);
        assert_ne!(f.io.writes[0].0, f.io.writes[1].0);
        assert_eq!(f.io.writes[0].1, f.io.writes[1].1);
        assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
        Ok(())
    }

    #[test]
    fn changed_pointer_or_atomic_rejection_preserves_key_without_sending_again() -> Result<()> {
        for reject_at_server in [false, true] {
            let mut f = Fixture::new()?;
            f.io.reject = reject_at_server;
            if !reject_at_server {
                f.io.records[0] = server_record(&f.io.records[0], &f.io.zone, "rotated-tag")?;
            }
            let mut session =
                UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
            assert!(session.advance(&mut f.io).is_err());
            assert_eq!(session.phase()?, &Phase::Rejected);
            assert_eq!(f.io.writes.len(), usize::from(reject_at_server));
            drop(session);
            let mut session =
                UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
            assert!(session.advance(&mut f.io).is_err());
            assert_eq!(
                session.credential().signing_key,
                f.plan.0.credential.signing_key
            );
            assert_eq!(f.io.writes.len(), usize::from(reject_at_server));
        }
        Ok(())
    }

    #[test]
    fn acceptance_or_http_success_is_not_fetch_verification_when_payload_changes() -> Result<()> {
        let mut f = Fixture::new()?;
        f.io.tamper_fetch = true;
        let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
        assert!(session.advance(&mut f.io).is_err());
        assert!(matches!(session.phase()?, Phase::Accepted { .. }));
        assert_eq!(f.io.writes.len(), 1);
        drop(session);
        let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
        assert!(session.advance(&mut f.io).is_err());
        assert!(!matches!(session.phase()?, Phase::FetchVerified { .. }));
        Ok(())
    }

    #[test]
    fn checkpoint_failures_poison_memory_and_reconcile_the_durable_attempt_after_reopen()
    -> Result<()> {
        for after_send in [false, true] {
            let mut f = Fixture::new()?;
            let mut session =
                UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
            if after_send {
                f.io.poison_ack = Some(f.denied.clone());
            } else {
                f.denied.store(true, Ordering::Release);
            }
            assert!(session.advance(&mut f.io).is_err());
            assert!(session.phase().is_err());
            assert!(session.advance(&mut f.io).is_err());
            assert_eq!(f.io.writes.len(), usize::from(after_send));
            f.denied.store(false, Ordering::Release);
            drop(session);
            let mut session =
                UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
            if after_send {
                assert!(matches!(session.phase()?, Phase::Attempted { .. }));
            } else {
                assert_eq!(session.phase()?, &Phase::Prepared);
            }
            f.io.poison_ack = None;
            session.advance(&mut f.io)?;
            assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
            assert_eq!(f.io.writes.len(), 1);
        }
        Ok(())
    }

    #[test]
    fn resume_refuses_changed_account_peer_request_or_plan_and_detects_ciphertext_tampering()
    -> Result<()> {
        let f = Fixture::new()?;
        let session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
        drop(session);
        for field in ["account", "peer", "request", "owner", "zone"] {
            let mut binding = f.plan.binding().clone();
            match field {
                "account" => {
                    binding.account_fingerprint = format!("SHA256:{}", STANDARD.encode([9u8; 32]))
                }
                "peer" => binding.peer_id = format!("SHA256:{}", STANDARD.encode([9u8; 32])),
                "request" => binding.request_sha256 = "f1".repeat(32),
                "owner" => binding.owner += 1,
                _ => binding.zone.owner = "different-owner".into(),
            }
            assert!(
                UploadStore::new(&f.directory, &f.backend)?
                    .resume(&binding)
                    .is_err()
            );
        }
        let mut changed = f.plan.clone();
        changed.0.public_sec1 = STANDARD.encode([0u8; 65]);
        assert!(
            UploadStore::new(&f.directory, &f.backend)?
                .prepare(changed)
                .is_err()
        );
        let path = f
            .directory
            .join(format!("upload-{}.enc", f.plan.binding().transaction));
        let mut bytes = read_bounded(&path)?;
        let end = bytes.len() - 1;
        bytes[end] ^= 1;
        atomic_write_private(&path, &bytes)?;
        assert!(
            UploadStore::new(&f.directory, &f.backend)?
                .resume(f.plan.binding())
                .is_err()
        );
        Ok(())
    }
}
